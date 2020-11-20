#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <fcntl.h>
#include <asm/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pwd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <limits.h>
#include "json.c"

#include "struct.h"

#define NETLINK_TEST 31 
#define NLMSG_SETECHO 0x11
#define NLMSG_COFIG 0x12
#define MAX_PAYLOAD 101
#define MAX_EVENTS 1024 /*Max. number of events to process at one go*/
#define LEN_NAME 16 /*Assuming that the length of the filename won't exceed 16 bytes*/
#define EVENT_SIZE  ( sizeof (struct inotify_event) ) /*size of one event*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME )) /*buffer to store the data of events*/
 

void *netlink_read_msg(void *args);
void netlink_send_msg(char *json);
int msg_prepare();

char * strtolower(char *str);
int sock_fd, bind_state, send_state, recv_state;
struct msghdr msg;
struct nlmsghdr *nlh = NULL;
struct sockaddr_nl src_addr, dest_addr;
struct iovec iov;
FILE *fp = 0;
char *content = 0;
json_value * value = 0;
_CC_Config cc_config;
pthread_t ntid, pathid;
typedef struct file_dir {
	char *path;
	char *file;
}file_dir;



void killdeal_func(){
	printf("The process is killed! \n");
	close(sock_fd);
	if(fp != NULL) fclose(fp);
	if(content != 0) free(content);
	if(value != 0) json_value_free(value);
	if(nlh != NULL) free(nlh);
	exit(0);
}

void netlink_user_send()
{
	int create_msg = msg_prepare();
	if (create_msg != 0) {
		printf("Send message error at creating message.\n");
		return;
	}
	
	send_state = sendmsg(sock_fd, &msg, 0);
        if(send_state == -1) {
                printf("send message error: %s\n",strerror(errno));
        }
        else {
                printf("send message ok\n");
        }

        memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));
        printf("waiting received!\n");

}

int msg_prepare()
{
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if(!nlh) {
		printf("malloc nlmsghdr error!\n");
		close(sock_fd);
		return -1;
	} 
	else {
		printf("malloc nlmsghdr ok\n");
	}
	
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD); 
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = NLMSG_COFIG;

	char content_addr[32];
	sprintf(content_addr, "%d", (unsigned int)&cc_config);
	strcpy(NLMSG_DATA(nlh), content_addr);

	//Fill in the netlink message payload
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

//	send_state = sendmsg(sock_fd, &msg, 0);
//        if(send_state == -1) {
//                printf("send message error: %s\n",strerror(errno));
//        }
//        else {
//                printf("send message ok\n");
//        }
//
//        memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));
//        printf("waiting received!\n");
//
	return 0;
}

int socket_create()
{
	sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_TEST);
	if(sock_fd == -1){
                printf("fail to initialize socket: %s\n", strerror(errno));
                return -1;
        }
        else {
                printf("socket initialized\n");
        }

        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();
        src_addr.nl_groups = 0;
        bind_state = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

        if(bind_state < 0){
                printf("bind failed: %s\n", strerror(errno));
                close(sock_fd);
                return -1;
        }
        else {
                printf("bind ok\n");
        }

	return 0;
}

int ip_file_parse(char *file)
{
	/*initialize config struct*/
//	signal(SIGALRM, sig_handler);
//	alarm(6);	

	cc_config.length = 0;
	cc_config.port = -1;
	cc_config.TCP = 0;
	cc_config.UDP = 0;


	/*read config file*/
	fp = fopen(file,"r");
	int flen;

	if(fp==NULL)
	{
		fclose(fp);
		printf("please input the path of config file!\n");
		exit(-1);
	}
	else
	{
		fseek(fp,0L,SEEK_END);
		flen = ftell(fp);
		content = (char*)malloc(flen+1);
		fseek(fp,0L,SEEK_SET);
		fread(content,flen,1,fp);
		content[flen]=0;
		fclose(fp);


		/*initialize the json paraser*/
		char error[256];
		json_settings settings;
		memset(&settings, 0, sizeof (json_settings));
		settings.settings = json_enable_comments;
		value = json_parse_ex(&settings, content, strlen(content), error);
		if (value == 0) {
			printf("wrong file format!\n");
			json_value_free(value);
			exit(-1);
		}
	}


	/*format check*/
	int i, j, k;
	for (i = 0; i < value->u.object.length; i++){
		json_object_entry obj = value->u.object.values[i];

	//protocol config
		if (strcmp("protocol", strtolower(obj.name)) == 0){
			if (obj.value->type == json_array){
				json_value**  arr_value = obj.value->u.array.values;
				for (j = 0; j < obj.value->u.array.length; j++){
					if (arr_value[j]->type == json_string){
						if (strcmp("tcp", strtolower(arr_value[j]->u.string.ptr)) == 0){
							cc_config.TCP = 1;
						}
						if (strcmp("udp", strtolower(arr_value[j]->u.string.ptr)) == 0){
							cc_config.UDP = 1;
						}
					}
					else {
						printf("protocol in the array should be a string!\n");
						goto format_error;
					}
				}
			}
		
			else if (obj.value->type == json_string){
				if (strcmp("tcp", strtolower((obj.value->u.array.values)[0]->u.string.ptr)) == 0){
					cc_config.TCP = 1;
				}
		
				if (strcmp("tcp", strtolower((obj.value->u.array.values)[0]->u.string.ptr)) == 0){
					cc_config.UDP = 1;
				}
			}
		
			else{
				printf("protocol should be an array or a string!\n");
				goto format_error;
			}
		}

		//global config
		else if (strcmp("*", obj.name) == 0){
			if (obj.value->type == json_object){
				for (k = 0; k < obj.value->u.object.length; k++){
					json_object_entry global_obj = obj.value->u.object.values[k];
				
					if (strcmp("port", strtolower(global_obj.name)) == 0){
						if (global_obj.value->type == json_integer){
							cc_config.port = global_obj.value->u.integer;
						}
		
						else {
							printf("port should be an integer!\n");
							goto format_error;
						}
					}
				}
			}
		
			else{
				printf("site should be an object!\n");
				goto format_error;
			}
		}

		//site config
			else {
				if (cc_config.length > 256){
					printf("rule number over 256 will be ignored!\n");
					break;
			}
		else {
			if (obj.value->type == json_object){

		//initialize site config
				_CC_Site *cc_site = &cc_config.arr[cc_config.length];
				cc_site->port = -1;
				cc_config.length += 1;

		//get name of IP and port
				strncpy(cc_site->IP, obj.name, 16);
				for (k = 0; k < obj.value->u.object.length; k++){
					json_object_entry site_obj = obj.value->u.object.values[k];
				
					if (strcmp("port", strtolower(site_obj.name)) == 0){
						if (site_obj.value->type == json_integer){
							cc_site->port = site_obj.value->u.integer;
						}
						else {
							printf("port should be an integer!\n");
							goto format_error;
						}	
					}
				}
			}
			
			else{
				printf("site should be an object!\n");
				goto format_error;
			}
		}
	}
	}
	json_value_free(value);
	free(content);

	printf("TCP: \t%d\n", cc_config.TCP);
	printf("UDP: \t%d\n", cc_config.UDP);
	printf("Length: %d\n", cc_config.length);
	printf("Port: \t%d\n", cc_config.port);
	int l;
		for(l = 0; l < cc_config.length; l++){
			printf("Site: \t%s:%d\n", cc_config.arr[l].IP, cc_config.arr[l].port);
		}


//	int sock_create = socket_create();
//	if (sock_create != 0) {
//		printf("Create socket failed.\n");
//		return -1;
//	}
//        pthread_create(&ntid, NULL, &netlink_read_msg, NULL);

//	void *tret;
//        pthread_join(ntid, &tret);
//        close(sock_fd);
        free(nlh);
        return 0;
format_error:
                printf("protocol type error!\n");
                json_value_free(value);
                free(content);
                return -1;

}

void *inotify_file(void *arg)
{
	int length, i = 0, wd;
	int fd;
	char buffer [BUF_LEN];


	struct file_dir file_path = *((struct file_dir *) arg);
	ip_file_parse(file_path.file);
	netlink_user_send();

	fd = inotify_init();
	if (fd < 0) {
		perror("Couldn't initialize inotify.\n");
	}

	wd = inotify_add_watch(fd, file_path.path, IN_CREATE | IN_MODIFY | IN_DELETE);
	
	if (wd == -1) {
		printf("Couldn't add watch to %s.\n", file_path.path);
	}
	else {
		printf("Watching: %s\n", file_path.path);
	}
	while (1) {
		i = 0;
		length = read(fd, buffer, BUF_LEN);

		if (length < 0) {
			perror("read");
		}
	
		while (i < length) {
			struct inotify_event *event = (struct inotify_event *)&buffer[i];
			if (event->len) {
				if (event->mask & IN_MODIFY) {
					if (event->mask & IN_ISDIR) {
						printf("The directory %s was modified.\n", event->name);
					}
					else {
						if (strcmp(event->name, "black.json") == 0) {
							 printf( "The file %s was modified with WD %d\n", event->name, event->wd );       
							ip_file_parse(file_path.file);
							netlink_user_send();
						}
					}
					
				}
			i += EVENT_SIZE + event->len;
			}
		}
	}
	
	inotify_rm_watch(fd, wd);
	close (fd);

	return 0;
}


void *netlink_user_recv(void *args)
{
	while(1){
        //Read message from kernel
		recv_state = recvmsg(sock_fd, &msg, 0);
		if(recv_state < 0){
                        printf("recv_state < 1\n");
                }
                time_t tt;
                char tmpbuf[80];
                tt = time(NULL);
                strftime(tmpbuf, 80, "%Y-%m-%d %H:%M:%S", localtime(&tt));
                printf("[%s]: %s", tmpbuf, NLMSG_DATA(nlh));
        }
}

char * strtolower(char *str){
	int i;
	for (i = 0; i < strlen(str); i++){
		str[i] = tolower(str[i]);
	}

	return str;
}

int main(int argc, char **argv){

/*chevck args*/
	if (argc != 3) {
		printf("please input the path of config file!\n");
		exit(-1);
	}
	signal(SIGTERM,killdeal_func);

	char *json, *path;
	json = argv[1];	
	path = argv[2];

	printf("Json file : %s, path: %s\n", json, path);
	struct file_dir file_path;
	file_path.path = argv[2];
	file_path.file = argv[1];

        int sock_create = socket_create();
        if (sock_create != 0) {
                printf("Create socket failed.\n");
                return -1;
        }
/*send message first time*/
//	ip_file_parse(json);
//	netlink_user_send();
//	pthread_create(&pathid, NULL, &sig_handler, &file_path);
	void  *sret;
	pthread_create(&pathid, NULL, &inotify_file, &file_path);
	pthread_create(&ntid, NULL, &netlink_user_recv, NULL);	
//	ip_file_parse(json);

	void *tret;
	pthread_join(pathid, &tret);
	pthread_join(ntid, &sret);	
	return 0;
}


