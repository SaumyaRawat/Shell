#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <setjmp.h>
//#include <errorno.h>
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

pid_t curpid;
jmp_buf env;
int infile,outfile;
char inputfile[10];
char output[10];
typedef struct process
{
    pid_t pid;
    int bg_flag;
    char proc_cmd[100];
}p;

p *jobs[1000];

typedef struct pipecommand
{
  char *argv;
  int redirectFlag;
}pc;

pid_t shell_pgid;
struct termios shell_tmodes;
int shell_terminal;
int shell_is_interactive;
int job_no;

void removeJob(pid_t pid)
{
    //printf("Came to remove job with pid: %d, the total jobs are %d\n",pid,job_no );
    int i=0,ptr=0;
    for(i=1;i<=job_no;i++)
    {
        if(jobs[i]->pid==pid)
        {
            jobs[i]->pid=0;
            //strcpy(jobs[i]->proc_cmd,"NULL");
            jobs[i]->bg_flag=0;
        }
    }
}

p *addJob(pid_t pid, char *proc_cmd, int bg_flag, int job_no)
{
    jobs[job_no]=malloc(sizeof(p));
    jobs[job_no]->pid=pid;
    strcpy(jobs[job_no]->proc_cmd,proc_cmd);
    jobs[job_no]->bg_flag=bg_flag;
}

char *findJobCmd(pid_t pid)
{
    int i=1;
    for(i=1;i<=job_no;i++)
    {
        if(jobs[i]->pid==pid)
        {
            return (jobs[i]->proc_cmd );
        }
    }
    return;
}

int findJobNo(pid_t pid)
{
    int i=1;
    for(i=1;i<=job_no;i++)
    {
        if(jobs[i]!=NULL && jobs[i]->pid==pid)
        {
            return (i);
        }
    }
    return -1;
}

int findJobPid(int job_index)
{
    int i=1,counter=1;
    pid_t pid;
/*    while(counter<job_index && i<=job_no)
    {
        i++;
        if(jobs[i]!=NULL && jobs[i]->pid!=0)
        {
            counter++;
        }
    } */
    if(jobs[job_index]!=NULL && jobs[job_index]->pid!=0)
    {
        return jobs[job_index]->pid;
    }
    return  -1;
}

void handler(int signo)
{
    //Will check if any of the childs have exited
   pid_t pid;
   int status;
   while((pid = waitpid(-1, &status, WNOHANG)) > 0)
   { //will enter as long as there are children that have just exited, if pid = 0 that means theres a child in background.
       char *proc_cmd=malloc(1025*1024*sizeof(char));
       strcpy(proc_cmd,findJobCmd(pid));
       WIFEXITED(status);
       if (status==0)
        {
            fprintf(stderr,"[proc %s with pid %d exited normally]\n",findJobCmd(pid),pid);
        }
        else
        {
            fprintf(stderr,"[proc %d exited with code %d]\n",pid, WEXITSTATUS(status));
        }
       /*remove the pid from jobs list */
        removeJob(pid);
   }
}

void sig_tstp(int signno)
{
    if(findJobNo(curpid)==-1)
    {
        fprintf(stderr, "\nNo foreground job running!\n");
        longjmp(env,2);
        return;
    }
    else
    {
        int i=findJobNo(curpid);
        if(jobs[i]->bg_flag==0) //fg process
        {
            jobs[i]->bg_flag=1;
            tcsetpgrp (STDIN_FILENO, getpgid(curpid));
            tcsetpgrp (STDOUT_FILENO, getpgid(curpid));
            printf("\n");
            longjmp(env,2);
        }
    }

    signal(SIGTSTP, sig_tstp);	/* reestablish signal handler */
	return;
}

void initShell()
{
    /* See if we are running interactively.  */
    shell_terminal = STDIN_FILENO;
    shell_is_interactive = isatty (shell_terminal);

    if (shell_is_interactive)
    {
      /* Loop until we are in the foreground.  */
      while (tcgetpgrp (shell_terminal) != (shell_pgid = getpgrp ()))
        kill (- shell_pgid, SIGTTIN);
      /* Ignore interactive and job-control signals.  */
      signal (SIGINT, SIG_IGN);
      signal (SIGQUIT, SIG_IGN);
//      signal (SIGTSTP, SIG_IGN);
      signal(SIGTSTP, sig_tstp);
      signal (SIGTTIN, SIG_IGN);
      signal (SIGTTOU, SIG_IGN);

      //signal (SIGCHLD, SIG_IGN);
      struct sigaction sa;
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = 0;
      sa.sa_handler = &handler;
      sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;

      if (sigaction(SIGCHLD, &sa, 0) == -1)
      {
        perror(0);
        //exit(1);
      }

      /* Put ourselves in our own process group.  */
      shell_pgid = getpid ();
      if (setpgid (shell_pgid, shell_pgid) < 0)
        {
          perror ("Couldn't put the shell in its own process group");
          exit (1);
        }

      /* Grab control of the terminal.  */
      tcsetpgrp (shell_terminal, shell_pgid);
      /* Save default terminal attributes for shell.  */
      tcgetattr (shell_terminal, &shell_tmodes);
    }
}

void getusername(char uname[]) //Function to get the username of the machine
{
    register struct passwd *pw;
    register uid_t uid;
    int c;

    uid = geteuid ();
    pw = getpwuid (uid);
    if (pw)
      {
        //char uname[100];
        strcpy ( uname,(pw->pw_name) );
        //printf("%s\n", uname);
        //return uname;
      }
    //fprintf (stderr,"%s: cannot find username for UID %u\n","whoami", (unsigned) uid);
    return;
    //exit (EXIT_FAILURE);
}

int isBackgroundJob( char *com)
{
    int len=strlen(com);
    if(com[len-1]=='&')
    {
        return 1;
    }
    return 0;
}

int isPipeJob( char *com)
{
    int len=strlen(com),pipes=0,i;
    for(i=0;i<len;i++)
    {
        if(com[i]=='|')
        {
            pipes++;
        }
    }
    return pipes;
}

int isRedirect( char *com)
{
    //printf("came to check for redirectFlag\n" );
    int len=strlen(com),counter=0,i;
    infile=0;
    outfile=0;
    int flag=0;
    for(i=0;i<len;i++)
    {
        if(com[i]=='>' && com[i+1]=='>') //append output
        {
            outfile=2;
            flag=1;
        }
        else if(com[i]=='>') //output
        {
            outfile=1;
            flag=1;
        }

        if(com[i]=='<') //input
        {
            infile=3;
            flag=1;
        }
    }
    return(flag);
}

int executeRedirect(char *cmd,char *com,int flag)
{
    char *token=malloc(1024*sizeof(char));
    if(outfile==1)
    {
        printf("Redirecting to output file!\n");
        sscanf(com, "%*[^>]> %[^\n]", output);
        outfile=1;
//        strcpy(output,token);
    }
    if (outfile==2)
    {
        printf("Redirecting to output file!\n");
        sscanf(com, "%*[^>]>> %[^\n]", output);
        outfile=2;
    }
    if(infile==3)
    {
        printf("Redirecting from input file!\n");
        sscanf(com, "%*[^<]< %[^>\n]", inputfile);
        infile=3;
        //strcpy(inputfile,token);
    }
}
int isBuiltInCommand(char *cmd)
{
    //printf("HERE 5\n");
    if (strcmp(cmd,"cd")==0)
    {
        return 1;
    }
    else if (strcmp(cmd,"pwd")==0)
    {
        return 1;
    }
    else if (strcmp(cmd,"echo")==0)
    {
        return 1;
    }
    else if (strcmp(cmd,"pinfo")==0)
    {
        return 1;
    }
    else if (strcmp(cmd,"jobs")==0)
    {
        return 1;
    }
    else if (strcmp(cmd,"kjob")==0)
    {
        return 1;
    }
    else if ( strcmp(cmd,"overkill")==0)
    {
        return 1;
    }
    else if( strcmp(cmd,"fg")==0)
    {
        return 1;
    }
    else if( strcmp(cmd,"history")==0)
    {
        return 1;
    }

    return 0;
}

void executeBuiltInCommand(char *cmd, char *savedTokens[],int no_of_tokens, char *homedir)
{
    if (strcmp("cd" , cmd)==0)
    {
        char *p;
        if( savedTokens[1]==NULL )  //implementing default behaviour of cd. If no argument is provided cd goes to home dir of shell
        {
            p=malloc( (strlen(homedir))* sizeof(char) );
            strcpy(p,homedir);
        }
        else
        {
            p=malloc( (strlen(savedTokens[1]))* sizeof(char) );
            char *oldstr=savedTokens[1];
            p=oldstr;
            int i=2,len,lenp=0,lenold=0;
            while(i<=no_of_tokens)
            {
                lenold=strlen(oldstr);
                len=strlen(savedTokens[i]);
                p=malloc( (len+lenp+1)* sizeof(char) );
                strcpy(p,oldstr);
                strcat(p,savedTokens[i]);
                strcat(p," ");
                oldstr=p;
                i++;
            }
        }

        if ( strcmp(p,"~") == 0)
        {
            strcpy(p,homedir);
        }
        if( chdir(p)!=0 ) //On success chdir returns 0
        {
            perror("Error! ");
        }
    }
    else if(strcmp("pwd", cmd)==0)
    {
        char pwd_addr[256];
        getcwd(pwd_addr , sizeof(pwd_addr) );
        printf("%s\n",pwd_addr);
    }
    else if(strcmp("echo", cmd)==0) //has been implemented considering the " " should not be printed.
    {
        char *p=malloc( (strlen(savedTokens[1]))* sizeof(char) );
        char *oldstr=savedTokens[1];
        p=oldstr;
        int i=2,len,lenp=0,lenold=0;
        while(i<=no_of_tokens)
        {
            lenold=strlen(oldstr);
            len=strlen(savedTokens[i]);
            p=malloc( (len+lenp+1)* sizeof(char) );
            strcpy(p,oldstr);
            strcat(p," ");
            strcat(p,savedTokens[i]);
            oldstr=p;
            i++;
        }
        len=strlen(p);
        if(strcmp(p,"~")==0)
        {
            printf("%s\n",homedir );
            return;
        }
        //printf("Final input for echo: %s\n",p );
            int j=0,k=0,flag=0;
            while(j<=len)
            {
                if(p[j]==34) //If P[J]== "
                {
                    flag=0;
                    for(k=j+1;k<=len&&p[k]!=34;k++);
                    if(k!=len+1)
                    {
                        //printf("Entered the if cuz k is %d\n",k );
                        for (k = j+1 ;k <= len && p[k]!=34; k++)
                        {
                            printf("%c",p[k]);
                        }
                    } //End only after matching " has been found of nothing has been found at all.
                    else
                    {
                        printf("\nError! Terminating \" not found!\n");
                        break;
                    }
                    j=k;
                }
                else
                {
                    printf("%c",p[j]);
                    flag=2;
                }
                j++;
            }
            printf("\n");
    }
    else if( strcmp("pinfo", cmd)==0 )
    {
        FILE *fp,*file;
        char *line = NULL;
        char *pidline = malloc(100 * sizeof(char));
        char *statusline = malloc(100 * sizeof(char));
        char *memline = malloc(100 * sizeof(char));
        size_t len;
        char read;

        if( savedTokens[1]==NULL )
        {
            fp=fopen("/proc/self/status", "r");
            file=fopen("/proc/self/smaps", "r");
        }
        else
        {
            //printf("%s\n",cmd );
            //printf("%s\n",savedTokens[1] );
            char *addline=malloc(50 * sizeof(char));
            char *addlinecopy=malloc(50 * sizeof(char));
            strcpy(addline,"/proc/");
            strcat(addline,savedTokens[1]);
            strcpy(addlinecopy,addline);
            strcat(addline,"/status");
            strcat(addlinecopy,"/smaps");
            file=fopen(addlinecopy, "r");
            fp=fopen(addline, "r");
            if (!fp)
            {
                fprintf(stderr, "Error! PID doesnt exist!\n" );
                return;
            }
        }
        int *flag=calloc(2,sizeof(int));
        while ((read = getline(&line, &len, fp)) != -1)
        {
            if ( strncmp("Pid:",line,4)==0 )
            {
                flag[0]=1;
                strcpy(pidline,line);
            }
            if ( strncmp("State:",line,6)==0 )
            {
                flag[1]=1;
                strcpy(statusline,line);
            }
            if ( strncmp("VmSize:",line,7)==0 )
            {
                flag[2]=1;
                strcpy(memline,line);
            }
        }
        if(flag[0]==1)
        {
            printf("%s\n",pidline );
	    }
    	else
    	{
    		fprintf(stderr,"PID not found!\n");
    	}
    	if(flag[1]==1)
            {
                printf("%s\n",statusline );
    	}
    	else
    	{
    		fprintf(stderr,"Status not found!\n");
    	}
    	if(flag[2]==1)
            {
                printf("%s\n",memline );
    	}
    	else
    	{
    		fprintf(stderr,"Virtual memory size not found!\n");
    	}
        if (!file)
        {
            fprintf(stderr, "Executable Path could not be found!\n" );
            return;
        }

        while ((read = getline(&line, &len, file)) != -1)
        {
            char *lcopy=malloc(strlen(line) * sizeof(char));
            strcpy(lcopy,line);
            char *token=strtok(lcopy, "/");
            int i=0;
            for(i=0;token[i]==line[i];i++);
            printf("Executable Path: %s\n",line+i );
            break;
            /* code */
        }
    }
    else if(strcmp("jobs",cmd)==0)
    {
        int i=1,j=1;
        for(i=1;i<=job_no;i++)
        {
            if(jobs[i]->pid!=0)
            {
            printf("[%d] %s [%d]\n",i,jobs[i]->proc_cmd,jobs[i]->pid );
            }
        }
    }
    else if(strcmp("kjob",cmd)==0)
    {
        if(no_of_tokens!=2)
        {
            fprintf(stderr, "Insufficient number of arguments!\n" );
            return;
        }

        int jobno=atoi(savedTokens[1]);
        int signo=atoi(savedTokens[2]);
        pid_t pid=findJobPid(jobno);
        if(pid!=-1)
        {
            if(signo==9)
            {
                removeJob(pid);
            }
            if(kill(pid,signo)!=0)
            {
                fprintf(stderr, "Error in sending signal! \n");
            }
        }
        else
        {
            perror("Process not found!");
        }
    }
    else if(strcmp("overkill",cmd)==0)
    {
        int i;
        pid_t pid;
        for(i=1;i<=job_no;i++)
        {
            pid=findJobPid(i);
            if(pid!=-1)
            {
                jobs[i]->pid=0;
                //strcpy(jobs[i]->proc_cmd,"NULL");
                jobs[i]->bg_flag=0;
            }
            if(pid!=-1 && pid!=0)
                kill(pid,9);
        }
    }
    else if(strcmp("fg",cmd)==0)
    {
        if(no_of_tokens!=1)
        {
            fprintf(stderr, "Insufficient number of arguments!\n" );
            return;
        }
        int jobno=0;
        if(savedTokens[1]!=NULL)
            jobno=atoi(savedTokens[1]);
        int pid=findJobPid(jobno);
        if(pid==-1)
        {
            fprintf(stderr, "PID not found!\n" );
        }
        else
        {
            int status;
            kill(getpgid(pid),SIGTSTP);

            //do
    		 //{
    			/* transfer controlling terminal */
                //removeJob(pid);
                int i=findJobNo(pid);
                jobs[i]->bg_flag=0;
    			if ( tcsetpgrp (STDIN_FILENO, getpgid(pid)) < 0)
                {
    				perror("tcsetpgrp 2");
    			}

    			if ( kill(pid, SIGCONT) < 0) {
    				perror("kill:sending SIGCONT");
    			}

                waitpid(pid,&status,WUNTRACED);

    		// } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    		/* Children completed: put the shell back in the foreground.  */
    		if( tcsetpgrp (STDIN_FILENO, getpgrp()) < 0) {
    			perror("tcsetpgrp 2");
    		}
        }
    }
    else if(strcmp(cmd,"history")==0)
    {
        int i=1;
        for(i=1;i<=job_no && jobs[i]!=NULL;i++)
        {
            printf("[%d] %s\n",i,jobs[i]->proc_cmd);
        }
    }
}

void executeCommand(char *cmd,char**savedTokens,int no_of_tokens)
{
    //execvp("name of command",argvector)
    int i=0;
    savedTokens[no_of_tokens+1]=NULL;
    execvp(savedTokens[0],savedTokens);
    //perror(savedTokens[0]);
}

int parseCommand(char *command, char **argv,int redirectFlag)
{
    int i=0,no_of_tokens=0;
    char *token=malloc(1024*sizeof(char));
    if(redirectFlag!=0)
    {
        executeRedirect(argv[0],command,redirectFlag);
    }
    token = strtok (command,">");
    token = strtok (command,"<");
    token = strtok (command," \t\n" );
    if(token==NULL)
        return;
    while (token!=NULL)
    {
        argv[i]=token;
        i++;
        token=strtok(NULL," \t\n");
    }
    argv[i]=NULL;
    no_of_tokens=i-1;
    char *cmd=argv[0];
    return(no_of_tokens);
}

int spawn_proc(int in,int out,pc node,int redirectFlag,char *homedir)
{
    int no_of_tokens=0,std_out;
    pid_t pid;
    char **argv=malloc ( 100 * sizeof(char)); //Number of tokens there can be
    pid=fork();
    if(pid<0)
    {
        fprintf(stderr, "Error in Piping!\n" );
    }
    else if(pid==0) /* Child */
    {
        infile=0;
        outfile=0;
        int random=isRedirect(node.argv);
        no_of_tokens=parseCommand(node.argv,argv,redirectFlag);
        if(in!=0)
        {
            dup2(in,0);
            close(in);
        }
        if(out!=1)
        {
            dup2(out,1);
            close(out);
        }
        if(outfile!=0)
        {
            int fd1;
            if(outfile==1)
            {
                fd1=open(output,O_CREAT|O_RDWR|O_TRUNC,00666);
                lseek(fd1, 0, SEEK_SET);
            }
            else if(outfile==2)
            {
                fd1=open(output,O_APPEND|O_CREAT|O_RDWR,00666);
            }
            if(fd1==-1)
            {
                fprintf(stderr, "Can't open file for output!\n");
                memset(output, 0, 10);
                outfile=0;
                return;
            }
            int std_out=dup(1);
            dup2(fd1,STDOUT_FILENO);
            close(fd1);
            memset(output, 0, 10);
            outfile=0;
            //redirectFlag=0;
        }
        if(infile==3)
        {
            int fd2;
            fd2=open(inputfile,O_RDWR,00666);
            if(fd2==-1)
            {
                fprintf(stderr, "Can't open file for input! 2\n");
                memset(inputfile, 0, 10);
                infile=0;
                return;
            }
            dup2(fd2,STDIN_FILENO);
            close(fd2);
            memset(inputfile, 0, 10);
            infile=0;
            //redirectFlag=0;
        }
        if(isBuiltInCommand(argv[0])==1)
        {
            job_no++;
            addJob(0,argv[0],0,job_no);
            executeBuiltInCommand(argv[0],argv,no_of_tokens,homedir);
            dup2(std_out,1);
            _exit(1);
        }
        else
            return (execvp(argv[0],argv));
    }
    return pid;
}

int executePipe( int no_of_pipes, char *com, int redirectFlag,char *homedir)
{
    pc *pcmd=malloc(100 * sizeof(pc));
    int fd[2];
    int isFirstPipe=1;
    int count = 0;
    char *commandline=malloc(1024*sizeof(char));
    strcpy(commandline,com);

    char *command=malloc(1024*sizeof(char));
    char **argv=malloc ( 100 * sizeof(char)); //Number of tokens there can be
    char *token=malloc(1024*sizeof(char));
    int i=0,j=0;
    command = strtok ( com,"|");  //first command
    while( command!=NULL)
    {
        pcmd[i].argv=command;
        pcmd[i].redirectFlag=isRedirect(command);
        command = strtok (NULL, "|");
        i++;
    }
    //Tokenise command for execution
    //parseCommand(pcmd[0].argv,argv);

    int in=0;
    for(i=0;i<no_of_pipes;i++)
    {
        pipe(fd);
        spawn_proc(in,fd[1],pcmd[i],pcmd[i].redirectFlag,homedir);
        close(fd[1]);
        in=fd[0];
    }
    if(in!=0)
        dup2(in,0);
    //last command
    infile=0;
    outfile=0;
    int random=isRedirect(pcmd[i].argv);
    int no_of_tokens=parseCommand(pcmd[i].argv,argv,pcmd[i].redirectFlag);
    int std_out=dup(1);
    if(outfile!=0)
    {
        int fd1;
        if(outfile==1)
        {
            fd1=open(output,O_CREAT|O_RDWR|O_TRUNC,00666);
            lseek(fd1, 0, SEEK_SET);
        }
        else if(outfile==2)
        {
            fd1=open(output,O_APPEND|O_CREAT|O_RDWR,00666);
        }
        if(fd1==-1)
        {
            fprintf(stderr, "Can't open file for output 1!\n");
            memset(output, 0, 10);
            outfile=0;
            return;
        }
        dup2(fd1,STDOUT_FILENO);
        close(fd1);
        memset(output, 0, 10);
        outfile=0;
        //redirectFlag=0;
    }
    if(infile==3)
    {
        int fd2;
        fd2=open(inputfile,O_RDWR,00666);
        if(fd2==-1)
        {
            fprintf(stderr, "Can't open file for input! 3\n");
            memset(inputfile, 0, 10);
            infile=0;
            return;
        }
        dup2(fd2,STDIN_FILENO);
        close(fd2);
        memset(inputfile, 0, 10);
        infile=0;
        //redirectFlag=0;
    }

    if(isBuiltInCommand(argv[0])==1)
    {
        job_no++;
        addJob(0,argv[0],0,job_no);
        executeBuiltInCommand(argv[0],argv,no_of_tokens,homedir);
        _exit(1);
        dup2(std_out,1);
        return(0);
    }
    else
        return(execvp(argv[0],argv));
}

int main(int argc, char *argv[])
{
    initShell();
    //signal(SIGCHLD, SIG_IGN);
    //Declarations
    int bytes_read,no_of_tokens,no_of_commands=0,redirectFlag=0;
    char uname[80],homedir[256],input[1024],hostname[80],tempstr[256],cwd[256];
    char *cmdline, *sentence, *line, *token,**savedTokens, **command, *cmd, *mcptr, *com;
    size_t length,homedirlen;
    pid_t childPid;
    //Change Shell home dir to ~
    getcwd(homedir , sizeof(homedir) );
    getusername(uname);
    homedirlen=strlen(homedir);
    strcpy(cwd,homedir);

/*    int ptr=0;
    for(ptr=0;ptr<=1000;ptr++)
    {
        jobs[ptr]=NULL;
    }*/
    int exit_flag=0;
    while (1)
    {
        sigset_t mask, prevmask;
        //Initialize mask with just the SIGCHLD signal
        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        sigprocmask(SIG_BLOCK, &mask, &prevmask); /*block SIGCHLD, get previous mask*/

        no_of_tokens=0;
        command=malloc ( 200 * sizeof(char)); //Number of commands there can be will be stored in 2D Array
        cmdline = (char *) malloc (1025 * sizeof(char));
        line = (char *) malloc (1025 * sizeof(char));
        cmd = (char *) malloc (1025 * sizeof(char));
        savedTokens=malloc ( 100 * sizeof(char)); //Number of tokens there can be
        strcpy(line,"\n");
        gethostname(hostname, sizeof(hostname));
        getcwd(cwd , sizeof(cwd) );
        //printf("PRINT THIS : %s\n",cwd+homedirlen );
        //printf("CWD: %d HOMEDIR: %d\n",strlen(cwd),strlen(homedir) );
        if( strncmp( cwd, homedir, homedirlen-1) == 0) // && strncmp( cwd, homedir, homedirlen-1)!=0) //If the current working directory is not ~
        {
            strcpy(tempstr,"~");
            //printf("HOME DIR IS: %s\n",tempstr );
            strcat(tempstr,cwd+homedirlen);
            strcpy(cwd, tempstr);
        }
        int jumper=setjmp(env);
        printf("<%s@%s:%s>",uname,hostname,cwd ); //PROMPT
        getline (&line, &length+1, stdin);
        //PARSING:
        //Stage 1: Handling multiple commands:

        int k=0;
            token = strtok (line, ";");
            command[k]=token;
            while ( token!=NULL )
            {
                command[k]=token;
                token = strtok (NULL,";");
                k++;
            }
            no_of_commands=k-1;
            if(no_of_commands==-1)
            {
                printf("Exiting main shell!\n");
                printf("\n");
                return 0;
            }
            else if(command[no_of_commands]!=NULL)
            {
                int len=strlen(command[no_of_commands]);
                command[no_of_commands][len-1]=0; //Last token gets an extra \n .. therefore removed here.
            }

        //STAGE 2:
        for(k=0;k<=no_of_commands;k++)
        {
/*            sigset_t mask, prevmask;
            //Initialize mask with just the SIGCHLD signal
            sigemptyset(&mask);
            sigaddset(&mask, SIGCHLD);
            sigprocmask(SIG_BLOCK, &mask, &prevmask); /*block SIGCHLD, get previous mask*/
            cmdline = command[k];
            com = (char *) malloc (1025 * sizeof(char));
            if(command[k]!=NULL)
                strcpy(com,command[k]); //com stores the whole command to be executed
            else
                com=NULL;

            //Stage 3: Piping
            int no_of_pipes=0;
            if(com!=NULL)
            {
                redirectFlag=isRedirect(com);
                no_of_pipes=isPipeJob(com);
            }
            if(no_of_pipes!=0)
            {
                int status;
                pid_t procid=fork();
                if(procid==0)
                {
                    executePipe(no_of_pipes,com,redirectFlag,homedir);
                }
                else
                {
                    sigprocmask(SIG_SETMASK, &prevmask, NULL); //Unblocking
                    wait(&status);
                }
            }
            else
            {
                int i=0;
                token = strtok(cmdline,">");
                token = strtok(cmdline,"<");
                token = strtok(cmdline," \t\n");
                if(token==NULL)
                {
                    no_of_commands=-1;
                }
                while(token != NULL)
                {
                    savedTokens[i]=token;
                    i++;
                    token = strtok (NULL, " \t\n");
                }
                if(i!=0)
                {
                    no_of_tokens=i-1;
                    cmd=savedTokens[0];
                }
                else
                {
                    no_of_tokens=0;
                    cmd=NULL;
                }

                int len=0;

                if(savedTokens[no_of_tokens]!=NULL)
                {
                    len=strlen(savedTokens[no_of_tokens]);
                }
                //savedTokens[no_of_tokens][len-1]=0; //Last token gets an extra \n .. therefore removed here.
                //if ((cmd!=NULL) && ((strcmp("exit",cmd)==0) ||  (strcmp("Exit",cmd)==0) || (strcmp("exit ",cmd)==0) || (strcmp("Exit ",cmd)==0)))
                if ((cmd!=NULL) && ((strcmp("quit",cmd)==0) || (strcmp("quit ",cmd)==0) || (strcmp(" quit",cmd)==0)))
                {
                    //exit(1);
                    exit_flag=1;
                    break;
                }

              /*int j=0;
                while(j<=no_of_tokens)
                {
                    printf("TOKEN %d: %s\n",j,savedTokens[j]);
                    j++;
                } */
        		//record command in history list (GNU readline history ?)
                int std_out;
                if(no_of_commands!=-1)
                {
            		if ( (cmd!=NULL) && isBuiltInCommand(cmd)==1 )
                    {
                            if(redirectFlag!=0)
                            {
                                executeRedirect(cmd,com,redirectFlag);
                            }
                            if(outfile!=0)
                            {
                                int fd1;
                                if(outfile==1)
                                {
                                    fd1=open(output,O_CREAT|O_RDWR|O_TRUNC,00666);
                                    lseek(fd1, 0, SEEK_SET);
                                }
                                else if(outfile==2)
                                {
                                    fd1=open(output,O_APPEND|O_CREAT|O_RDWR,00666);
                                }
                                if(fd1==-1)
                                {
                                    fprintf(stderr, "Can't open file %s for output!\n",output);
                                    memset(output, 0, 10);
                                    outfile=0;
                                    continue;
                                }
                                std_out=dup(1);
                                dup2(fd1,STDOUT_FILENO);
                                close(fd1);
                                memset(output, 0, 10);
                                outfile=0;
                            }
                            if(infile==3)
                            {
                                int fd2;
                                fd2=open(inputfile,O_RDWR,00666);
                                if(fd2==-1)
                                {
                                    fprintf(stderr, "Can't open file for input! 4\n");
                                    memset(inputfile, 0, 10);
                                    infile=0;
                                    continue;
                                }
                                dup2(fd2,STDIN_FILENO);
                                close(fd2);
                                memset(inputfile, 0, 10);
                                infile=0;
                            }
                            job_no++;
                            addJob(0,cmd,0,job_no);
                            executeBuiltInCommand(cmd,savedTokens,no_of_tokens,homedir);
                            dup2(std_out,1);
                    }
                    else
                    {
                        if((com!=NULL) && isBackgroundJob(com)==1)
                        {
                            savedTokens[no_of_tokens]=NULL;
                        }
                        int status;
            		    childPid = fork();
                        switch (childPid)
                        {
                            case 0: //Child Process
                                //setpgid(0,0);  //make the current process the group leader
                                //tcsetpgrp(0,getpid());
                                if(redirectFlag!=0)
                                {
                                    executeRedirect(cmd,com,redirectFlag);
                                }
                                if(outfile!=0)
                                {
                                    int fd1;
                                    if(outfile==1)
                                    {
                                        fd1=open(output,O_CREAT|O_RDWR|O_TRUNC,00666);
                                        lseek(fd1, 0, SEEK_SET);
                                    }
                                    else if(outfile==2)
                                    {
                                        fd1=open(output,O_APPEND|O_CREAT|O_RDWR,00666);
                                    }
                                    if(fd1==-1)
                                    {
                                        fprintf(stderr, "Can't open file for output 6!\n");
                                        memset(output, 0, 10);
                                        outfile=0;
                                        continue;
                                    }
                                    dup2(fd1,STDOUT_FILENO);
                                    close(fd1);
                                    memset(output, 0, 10);
                                    outfile=0;
                                }
                                if(infile==3)
                                {
                                    int fd2;
                                    printf("%s\n",inputfile);
                                    fd2=open(inputfile,O_RDWR,00666);
                                    if(fd2==-1)
                                    {
                                        fprintf(stderr, "Can't open file for input! 5\n");
                                        memset(inputfile, 0, 10);
                                        infile=0;
                                        continue;
                                    }
                                    dup2(fd2,STDIN_FILENO);
                                    close(fd2);
                                    memset(inputfile, 0, 10);
                                    infile=0;
                                }
                                executeCommand(cmd,savedTokens,no_of_tokens); //calls execvp
                                /* if exec returns there was an error. */
                                perror(savedTokens[0]);
                                exit(-1);

                            case -1:
                                perror("Fork");
                                return -1;

                            default: //In Parent
                                sigprocmask(SIG_SETMASK, &prevmask, NULL); //Unblocking
                                //handler(childPid,cmd,job_no,jobs); //Check if any of the childs exited
                                if (isBackgroundJob(com)==1)
                                {
                                    setpgid(childPid,childPid); //added the background process to its own group
                                    //tcsetpgrp(0,childPid);
                                    savedTokens[no_of_tokens]=NULL;
                                //    add pid to some list to track jobs
                                    job_no++;
                                    printf("[%d][proc %d started]\n",job_no, childPid);
                                    addJob(childPid,cmd,1,job_no);
    //                                sigprocmask(SIG_SETMASK, &prevmask, NULL); //Unblocking
                                }
                                else
                                {
                                    //Add foreground jobs to list:
                                    job_no++;
                                    //printf("Parent: Here total jobs are %d \n",job_no );
                                    addJob(childPid,cmd,0,job_no);
                                    curpid=childPid;
                                //    printf("jobs[%d]->cmd: %s\n",job_no,jobs[job_no]->cmd);
                                    sigprocmask(SIG_SETMASK, &prevmask, NULL); //Unblocking
                                    pid_t wpid;
                                    do
                                    {
                                        wpid = waitpid(childPid, &status, WUNTRACED); //WUNTRACED->status of child processes will be reported here!
                                    } while (!WIFEXITED(status) && !WIFSIGNALED(status)); //WIFEXITED reports normal termination and //WIFSIGNALED not 0  status if child process stopped but wasnt caught!
                                    removeJob(wpid);
                                    curpid=getpid();
                                    //printf("I am removing the fg job with pid %d\n",wpid );
                                    //waitpid (childPid);
                                    //printf("HERE! 2\n" );
                                }
                        }
                    }
                }
            }
        }//end of k loop
        if(exit_flag==1)
            break;

        //free(line); //
    } //End of while loop
    return 0;
}
