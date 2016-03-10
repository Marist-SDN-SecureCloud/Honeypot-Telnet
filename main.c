#include "common.h"
#include "Authenticate.h"
#include "telnet-protocol.h"
#include "settings.h"
#include <sys/mount.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/wait.h>


#define USER_ADD 1
#define USER_DEL 2
#define USER_LIST 3

//Older linux systems will lack 'lazy unmounts' (MNT_DETACH)
//so catch this and handle it here
#ifndef MNT_DETACH
#define MNT_DETACH 0
#endif

int g_argc;
char **g_argv;
int PidFile;

char *SessionSubstituteVars(char *RetStr, char *Format, TSession *Session)
{
ListNode *Vars;
char *Tempstr=NULL;

Tempstr=CopyStr(RetStr,"");
Vars=ListCreate();

Tempstr=SetStrLen(Tempstr,4096);
gethostname(Tempstr, 4096);
SetVar(Vars,"ServerHost",Tempstr);
Tempstr=FormatStr(Tempstr,"%d",Settings.Port);
SetVar(Vars,"ServerPort",Tempstr);
SetVar(Vars,"Interface",Settings.Interface);
SetVar(Vars,"Date",GetDateStr("%Y/%m/%d",NULL));
SetVar(Vars,"Date",GetDateStr("%H:%M:%S",NULL));
SetVar(Vars,"DateTime",GetDateStr("%Y/%m/%d %H:%M:%S",NULL));


//This function might be called before session setup, where all
//that we can substitute are 'interface' and 'serverhost/port' etc
if (Session)
{
	SetVar(Vars,"ClientHost",Session->ClientHost);
	SetVar(Vars,"ClientIP",Session->ClientIP);
	SetVar(Vars,"ClientMAC",Session->ClientMAC);
	SetVar(Vars,"ServerIP",Session->ServerIP);
	SetVar(Vars,"User",Session->User);
	SetVar(Vars,"RealUser",Session->RealUser);
}

Tempstr=SubstituteVarsInString(Tempstr,Format,Vars,0);

ListDestroy(Vars,DestroyString);

return(Tempstr);
}


int Login(TSession *Session)
{
char *Tempstr=NULL;
int result, RetVal=FALSE;
time_t Duration, Start, Now, LastActivity;


Session->User=CopyStr(Session->User,NULL);
Session->Password=CopyStr(Session->Password,NULL);

//Clear out any crap
Tempstr=SetStrLen(Tempstr,4096);
result=TelnetReadBytes(Session->S, Tempstr, 4096, TNRB_ECHO | TNRB_NOPTY | TNRB_NONBLOCK);

while (StrLen(Session->User)==0)
{
  time(&LastActivity);

  if (Settings.IdleTimeout > 0) STREAMSetTimeout(Session->S, Settings.IdleTimeout);

	if (Settings.Flags & FLAG_CHALLENGE)
	{
		Session->Challenge=GenerateSalt(Session->Challenge, 24);
		Tempstr=MCopyStr(Tempstr, "Challenge/Response String: ", Session->Challenge, "\r\n", NULL); 
		STREAMWriteLine(Tempstr, Session->S); 
	}


	STREAMWriteLine("login: ", Session->S); STREAMFlush(Session->S);
	result=TelnetReadBytes(Session->S, Tempstr, 4096, TNRB_ECHO | TNRB_NOPTY);
	if (result > 0)
	{
		Session->User=CopyStrLen(Session->User, Tempstr, result);
		StripTrailingWhitespace(Session->User);
	}

  time(&Now);
  if ((Settings.IdleTimeout > 0) && ((Now - LastActivity) > Settings.IdleTimeout)) break;

}

STREAMWriteLine("Password: ", Session->S); STREAMFlush(Session->S);
result=TelnetReadBytes(Session->S, Tempstr, 4096, TNRB_NOPTY);
if (result > 0)
{
	Session->Password=CopyStrLen(Session->Password, Tempstr, result);
	StripTrailingWhitespace(Session->Password);
}

STREAMWriteLine("\r\n",Session->S);

if ((Settings.Flags & FLAG_LOCALONLY) && (! StrLen(Session->ClientMAC)))
{
	syslog(Settings.ErrorLogLevel,"%s@%s NOT LOCAL. Denying Login.",Session->User,Session->ClientIP);
}
else if (Settings.Flags & FLAG_HONEYPOT){
	//Original syslog(Settings.ErrorLogLevel,"%s@%s login denied (honeypot mode): user=%s pass=%s",Session->User,Session->ClientIP,Session->User,Session->Password);
	//Eric Wedaa added the following line to log to the LongTail honeypot consolidation server
	syslog(Settings.ErrorLogLevel,"IP: %s TelnetLog: Username:%s Password:%s",Session->ClientIP,Session->User,Session->Password);
}
else if (
					(! (Session->Flags & FLAG_DENYAUTH)) &&
					(Authenticate(Session))
)  RetVal=TRUE; 

//Now that we've used the password, blank it from memory!
result=StrLen(Session->Password);
if (result > 0) memset(Session->Password,0,result);


DestroyString(Tempstr);
//STREAMDisassociateFromFD(S);

return(RetVal);
}




void RmDirPath(char *path)
{
char *Tempstr=NULL, *ptr;

ptr=path;
while (*ptr=='/') ptr++;
Tempstr=CopyStr(Tempstr,ptr);

ptr=strrchr(Tempstr,'/');
while (ptr)
{
	rmdir(Tempstr);
	*ptr='\0';
	ptr=strrchr(Tempstr,'/');
}
if (StrLen(Tempstr)) rmdir(Tempstr);

DestroyString(Tempstr);
}



void UndoBindMounts(char *DirList, int Flags)
{
char *UmountList=NULL, *Token=NULL, *Tempstr=NULL, *ptr, *dptr;

//Reverse dir list so we unmount in reverse order
//to the mounts
ptr=GetToken(DirList,",",&Token,0);
while (ptr)
{
	dptr=Token;
	Tempstr=MCopyStr(Tempstr,dptr,",",UmountList,NULL);
	UmountList=CopyStr(UmountList,Tempstr);
	ptr=GetToken(ptr,",",&Token,0);
}


ptr=GetToken(UmountList,",",&Token,0);
while (ptr)
{
	dptr=strrchr(Token,':');
	if (dptr) dptr++; 
	else dptr=Token;

	while (*dptr=='/') dptr++;
	umount2(dptr, MNT_DETACH);
	RmDirPath(dptr);
	ptr=GetToken(ptr,",",&Token,0);
}

DestroyString(Token);
}



void DoBindMounts(char *DirList, int Flags)
{
char *MntSrc=NULL, *MntDest=NULL, *ptr, *dptr;

ptr=GetToken(DirList,",",&MntSrc,0);
while (ptr)
{
	//if there's a ':' character in the mount definition, then it means that
	//we're mounting a directory in a different place than it would normally exist.
	//the default is to mount, say, /usr/lib as /usr/lib in the chroot. But if we
	//are passed /home/mylibs:/lib then we mount /home/mylibs as /lib in the chroot
	dptr=strrchr(MntSrc,':');
	if (dptr) 
	{
		*dptr='\0';
		dptr++;
	}
	else dptr=MntSrc;

	while (*dptr == '/') dptr++;

	MntDest=CopyStr(MntDest,dptr);
	MntDest=SlashTerminateDirectoryPath(MntDest);
	MakeDirPath(MntDest,0555);

	//Try a remount first. This prevents us mounting over and over
	//on the same mount point
	if (mount(MntSrc,MntDest,"",MS_BIND | MS_REMOUNT,"") !=0)
	{
		mount(MntSrc,MntDest,"",MS_BIND,"");
	}

	ptr=GetToken(ptr,",",&MntSrc,0);
}

DestroyString(MntSrc);
DestroyString(MntDest);
}



void SetWindowSize(int fd)
{
struct winsize w;

if (Settings.WinWidth && Settings.WinLength)
{
		w.ws_col=Settings.WinWidth;
		w.ws_row=Settings.WinLength;
    ioctl(fd, TIOCSWINSZ, &w);
}

Settings.Flags &= (~FLAG_WINSIZE);
}


void SetupEnvironment(TSession *Session)
{
char *Token=NULL, *ptr, *dptr;

setenv("LD_LIBRARY_PATH","/usr/local/lib:/usr/lib:/lib",1);
setenv("HOME",Session->HomeDir,TRUE);
if (StrLen(Settings.TermType)) setenv("TERM",Settings.TermType,TRUE);

SetWindowSize(0);

ptr=GetToken(Settings.Environment,",",&Token,GETTOKEN_QUOTES);
while (ptr)
{
	dptr=strchr(Token,'=');
	if (dptr)
	{
		*dptr='\0';
		dptr++;
	}
	else dptr="";
	setenv(Token, dptr, TRUE);
	ptr=GetToken(ptr,",",&Token,GETTOKEN_QUOTES);
}

DestroyString(Token);
}



int LaunchPtyFunc(void *p_Session)
{
TSession *Session;

Session=(TSession *) p_Session;
SetupEnvironment(Session);

//must chroot before we switch user, or we lack the permission to do so!
if (Settings.Flags & FLAG_CHHOME) 
{
	chroot(".");
	setenv("HOME",".",TRUE);
}


//switch group first, as we need to be root to do that
if (Session->GroupID) 
{
	if (setgid(Session->GroupID) !=0) exit(1);
}

//now switch user
if (Session->RealUserUID > 0)
{
if (setresuid(Session->RealUserUID,Session->RealUserUID,Session->RealUserUID) !=0) exit(1);
}

return(execl(Session->Shell,Session->Shell,NULL));
}



//Every telnet session has two processes. One is the 'shell' or program that is being 
//accessed via telnet. Then there is one that reads data from the telnet socket, 
//strips/interprets it, and feeds the results to the 'shell'.
//This function is the latter process, it launches the shell in 'LaunchPtyFunc'.

void RunTelnetSession(TSession *Session)
{
STREAM *Local, *S;
char *Tempstr=NULL;
int result, fd;
ListNode *Streams;
struct passwd *pwent;
struct group *grent;
struct timeval tv;
time_t Duration, Start, Now, LastActivity;

time(&Start);
LastActivity=Start;
Streams=ListCreate();
ListAddItem(Streams,Session->S);

//if '-real-user' was specified on the command-line, then this overrides
//anything read from password files
if (Settings.Flags & FLAG_FORCE_REALUSER)
{
	Session->RealUser=CopyStr(Session->RealUser,Settings.RealUser);
}

//Get User Details before we chroot! 
if (StrLen(Session->RealUser))
{
    pwent=getpwnam(Session->RealUser);
		if (! pwent)
		{
			syslog(Settings.InfoLogLevel,"Failed to lookup RealUser '%s' for user '%s'",Session->RealUser,Session->User);
			exit(1);
		}
		Session->RealUserUID=pwent->pw_uid;
		Session->GroupID=pwent->pw_gid;
}


//if '-shell' was specified on the command-line, then this overrides
//anything read from password files
if (Settings.Flags & FLAG_FORCE_SHELL)
{
	Session->Shell=CopyStr(Session->Shell,Settings.RealUser);
}


if (Settings.Flags & FLAG_DYNHOME)
{
	Session->HomeDir=SessionSubstituteVars(Session->HomeDir,Settings.DynamicHomeDir,Session);
	Session->HomeDir=SlashTerminateDirectoryPath(Session->HomeDir);
	MakeDirPath(Session->HomeDir,0777);
}

//CD to the user's home directory
if (StrLen(Session->HomeDir)) 
{
	chdir(Session->HomeDir);
}

DoBindMounts(Settings.BindMounts,0);

//This login script allows setting up any aspects of the environment before we launch the shell. For instance it 
//might be used to copy files into the chroot environment before chrooting
if (StrLen(Settings.LoginScript)) system(Settings.LoginScript);


//LAUNCH THE SHELL FUNCTION!!! This launches the program that the telnet user is 'speaking' to.
//If chhome is active, then it will be chrooted into the user's home directory


PseudoTTYSpawnFunction(&fd, LaunchPtyFunc, Session,  TTYFLAG_CANON | TTYFLAG_ECHO | TTYFLAG_CRLF | TTYFLAG_LFCR | TTYFLAG_IGNSIG);
Local=STREAMFromFD(fd);
STREAMSetTimeout(Local,0);


//Might as well chroot on this side of the pipe too, unless we have a 'LogoutScript'
//Logout scripts exist to allow copying stuff back out of the chroot when the session is
//finished. We can't do this if we chroot this side as well as the 'shell' side
if (
		(! StrLen(Settings.LogoutScript)) &&
		(Settings.Flags & FLAG_CHHOME) 
	) chroot(".");

//DON'T SWITCH USER. NEED root TO UNBIND MOUNTS
//if (setreuid(Session->RealUserUID,Session->RealUserUID) !=0) exit(1);

ListAddItem(Streams,Local);


Tempstr=SetStrLen(Tempstr,4096);
while (1)
{
	if (Settings.IdleTimeout) tv.tv_sec=Settings.IdleTimeout;
	else tv.tv_sec=3600 * 24;
  S=STREAMSelect(Streams,&tv);
	time(&Now);
  if (S)
  {
    if (S==Session->S)
		{
			result=TelnetReadBytes(Session->S, Tempstr, 4096, TNRB_NONBLOCK);
			if (result ==-1) break;
			STREAMWriteBytes(Local,Tempstr,result);
		}
    else 
		{
			result=STREAMReadBytes(Local,Tempstr,4096);
			if (result < 0) break;
			STREAMWriteBytes(Session->S,Tempstr,result);

    if (result < 0) break;
		}
		if (Settings.Flags & FLAG_WINSIZE) SetWindowSize(Session->S->out_fd);
		LastActivity=Now;
  }

	
	if ((Settings.IdleTimeout > 0) && ((Now - LastActivity) > Settings.IdleTimeout)) break;
}

if (StrLen(Settings.LogoutScript)) system(Settings.LogoutScript);
if (Settings.Flags & FLAG_UNMOUNT) UndoBindMounts(Settings.BindMounts, 0);
if (Settings.Flags & FLAG_DYNHOME) rmdir(Session->HomeDir);

Duration=time(NULL) - Start;
syslog(Settings.InfoLogLevel,"%s@%s logged out after %d secs",Session->User,Session->ClientIP, Duration);

STREAMClose(Session->S);
STREAMClose(Local);
DestroyString(Tempstr);
}


void GetClientHardwareAddress(TSession *Session)
{
STREAM *S;
char *Tempstr=NULL, *Token=NULL, *ptr;

S=STREAMOpenFile("/proc/net/arp",O_RDONLY);
if (S)
{
	Tempstr=STREAMReadLine(Tempstr,S);
	Tempstr=STREAMReadLine(Tempstr,S);
	while (Tempstr)
	{
		ptr=GetToken(Tempstr,"\\S",&Token,0);
		if (strcmp(Token,Session->ClientIP)==0)
		{
		//HW Type
		ptr=GetToken(ptr,"\\S",&Token,0);
		//Flags
		ptr=GetToken(ptr,"\\S",&Token,0);

		//MAC
		ptr=GetToken(ptr,"\\S",&Session->ClientMAC,0);
			
		}
	Tempstr=STREAMReadLine(Tempstr,S);
	}
	STREAMClose(S);
}

DestroyString(Tempstr);
DestroyString(Token);
}


int FnmatchInList(char *List, char *Item)
{
char *Token=NULL, *ptr;
int RetVal=FALSE;

if (! StrLen(Item)) return(FALSE);
ptr=GetToken(List,",",&Token,0);
while (ptr)
{
	if (fnmatch(Token,Item,0)==0) 
	{
	RetVal=TRUE;
	break;
	}
	ptr=GetToken(ptr,",",&Token,0);
}

DestroyString(Token);
return(RetVal);
}



int CheckClientPermissions(TSession *Session)
{
int RetVal=TRUE;


if (StrLen(Settings.AllowIPs) || StrLen(Settings.AllowMACs)) RetVal=FALSE;


if (StrLen(Settings.AllowIPs))
{
	if (FnmatchInList(Settings.AllowIPs, Session->ClientIP)) RetVal=TRUE;
}

if (StrLen(Settings.DenyIPs))
{
	if (FnmatchInList(Settings.DenyIPs, Session->ClientIP)) 
	{
		RetVal=FALSE;
		syslog(Settings.ErrorLogLevel,"%s In IP Deny List. Denying Login.",Session->ClientIP);
	}
}

if (StrLen(Settings.AllowMACs))
{
	if (FnmatchInList(Settings.AllowMACs, Session->ClientMAC)) RetVal=TRUE;
}

if (StrLen(Settings.DenyMACs))
{
	if (FnmatchInList(Settings.DenyMACs, Session->ClientMAC)) 
	{
		RetVal=FALSE;
		syslog(Settings.ErrorLogLevel,"%s/%s In MAC Deny List. Denying Login.",Session->ClientIP,Session->ClientMAC);
	}
}

return(RetVal);
}


uid_t JailAndSwitchUser(int Flags, char *User, char *JailDir)
{
struct passwd *pwent=NULL;
uid_t UID=0;

if (! StrLen(User)) pwent=getpwnam("nobody");
else pwent=getpwnam(User);

chdir(JailDir);

if (Flags & FLAG_CHROOT) chroot(".");

if (pwent) 
{
	UID=pwent->pw_uid;
	if (setgid(pwent->pw_gid) !=0) exit(20);
	if (setresuid(UID,UID,UID) !=0) exit(20);
}
else exit(20);

return(UID);
}



void HandleClient()
{
TSession *Session;
char *Tempstr=NULL;
int i;


	Session=(TSession *) calloc(1,sizeof(TSession));
	Session->Shell=CopyStr(Session->Shell,Settings.DefaultShell);
	Session->S=STREAMFromDualFD(0,1);
	STREAMSetTimeout(Session->S,0);
	GetSockDetails(0, &Session->ServerIP, &i, &Session->ClientIP, &i);
	GetClientHardwareAddress(Session);
	Session->ClientHost=CopyStr(Session->ClientHost,IPStrToHostName(Session->ClientIP));

	if (StrLen(Session->ClientMAC)) syslog(Settings.InfoLogLevel,"connection from: %s (%s / %s)", Session->ClientHost, Session->ClientIP, Session->ClientMAC);
	else syslog(Settings.InfoLogLevel,"connection from: %s (%s)", Session->ClientHost, Session->ClientIP);

	if (! CheckClientPermissions(Session)) Session->Flags |= FLAG_DENYAUTH;

	chdir(Settings.ChDir);
	if (StrLen(Settings.ChDir)==0) chdir(Settings.ChDir);
	if (Settings.Flags & FLAG_CHROOT) chroot(".");

	TelnetSendNegotiation(Session->S, TELNET_WONT, TELNET_LINEMODE);
	TelnetSendNegotiation(Session->S, TELNET_WILL, TELNET_NOGOAHEAD);
	//TelnetSendNegotiation(Session->S, TELNET_DONT, TELNET_LINEMODE);
	TelnetSendNegotiation(Session->S, TELNET_WILL, TELNET_ECHO);

	if (StrLen(Settings.Banner)) 
	{
		Tempstr=SessionSubstituteVars(Tempstr,Settings.Banner,Session);
		STREAMWriteLine(Tempstr,Session->S);
		STREAMWriteLine("\r\n",Session->S);
	}

	if (strcmp(Settings.AuthMethods,"open")==0) Session->Flags |= FLAG_AUTHENTICATED;
	else
	{
		for (i=0; i < Settings.AuthTries; i++)
		{
			if (Login(Session)) break;
			printf("\r\nLogin incorrect\r\n"); fflush(NULL);

			if (! (Settings.Flags & FLAG_DENYAUTH))  syslog(Settings.ErrorLogLevel,"%s@%s login failed: tries used %d/%d",Session->User,Session->ClientIP,i,Settings.AuthTries);
			sleep(Settings.AuthDelay);
		}
	}


	if (Session->Flags & FLAG_AUTHENTICATED)
	{
		syslog(Settings.InfoLogLevel,"%s@%s logged in after %d tries",Session->User,Session->ClientIP,i);
		RunTelnetSession(Session);
	}
	else syslog(Settings.ErrorLogLevel,"login from %s failed after %d tries",Session->ClientIP,i);

	DestroyString(Tempstr);
	free(Session);
	_exit(0);
}

void SetupPidFile()
{
char *Tempstr=NULL;


Tempstr=SessionSubstituteVars(Tempstr,Settings.PidFile,NULL);

PidFile=WritePidFile(Tempstr);
DestroyString(Tempstr);
}

static void default_signal_handler(int sig) { /* do nothing */  }

void PTelnetDServerMode()
{
int listensock, fd, i;
struct sigaction sigact;
char *Tempstr=NULL, *IPStr=NULL;

listensock=InitServerSock(Settings.Interface,Settings.Port);
if (listensock==-1)
{
	printf("ERROR: Cannot bind to port %d on interface %s\n",Settings.Port,Settings.Interface);
	exit(3);
}

if (! (Settings.Flags & FLAG_NODEMON)) demonize();

SetupPidFile();

if (Settings.Flags & FLAG_HONEYPOT) JailAndSwitchUser(FLAG_CHROOT, Settings.RealUser, Settings.ChDir);

while (1)
{
/*Set up a signal handler for SIGCHLD so that our 'select' gets interrupted when something exits*/
sigact.sa_handler = default_signal_handler;   
sigemptyset(&sigact.sa_mask);
sigact.sa_flags = 0;
sigaction(SIGCHLD, &sigact, NULL);

if (FDSelect(listensock, SELECT_READ, NULL)) 
{
	fd=TCPServerSockAccept(listensock, &IPStr);
	if (fork()==0) 
	{
		//Sub processes shouldn't keep the pid file open, only the parent server
		//should
		close(PidFile);

		//if we've been passed a socket, then make it into stdin/stdout/stderr
		//but don't do this is fd==0, because then this has already been done by inetd
		close(0);
		close(1);
		close(2);
		dup(fd);
		dup(fd);
		dup(fd);

		//Having dupped it we no longer need to keep this copy open
		close(fd);
		Tempstr=MCopyStr(Tempstr, g_argv[0]," ",IPStr,NULL);
		for (i=0; i <g_argc; i++) memset(g_argv[i],0,StrLen(g_argv[i]));
		strcpy(g_argv[0],Tempstr);

		//In case logging demon was restarted, ensure we have connection before we chroot
		//Eric Wedaa modified the following line to log to the LongTail honeypot consolidation server
		openlog("ptelnetd",LOG_PID|LOG_NDELAY,LOG_AUTH);
		HandleClient();

		//Should be redundant, but if something goes wrong in HandleClient, we might want this
		//exit call
		_exit(0);
	}
	close(fd);
}
waitpid(-1,NULL,WNOHANG);
}

}



main(int argc, char *argv[])
{
g_argc=argc;
g_argv=argv;

//LOG_NDELAY to open connection immediately. That way we inherit the connection
//when we chroot
//Eric Wedaa modified the following line to log to the LongTail honeypot consolidation server
openlog("ptelnetd",LOG_PID|LOG_NDELAY,LOG_AUTH);

SettingsInit();
SettingsParseCommandLine(argc, argv);

//Check if settings are valid. Abort if the user has asked for something stupid and/or dangerous.
if (! SettingsValid()) exit(2);


if (Settings.Flags & FLAG_INETD)
{
	if (Settings.Flags & FLAG_HONEYPOT) JailAndSwitchUser(FLAG_CHROOT, Settings.RealUser, Settings.ChDir);
	HandleClient();
}
else PTelnetDServerMode();
}

