#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PASSWD_LEN 12
#define BAD_CHARS -1
#define BAD 0
#define TRUE 1
#define FALSE 0
#define NULL_CHAR '\0'

// DES replacement cipher
// The function E takes 4 by
// writes 4 bytes to *out
void E(char *in, char *out)
{
	out[0]=(in[0]&0x80)^(((in[0]>>1)&0x7F)^((in[0])&0x7F));
	out[1]=((in[1]&0x80)^((in[0]<<7)&0x80))^(((in[1]>>1)&0x7F)^((in[1])&0x7F));
	out[2]=((in[2]&0x80)^((in[1]<<7)&0x80))^(((in[2]>>1)&0x7F)^((in[2])&0x7F));
	out[3]=((in[3]&0x80)^((in[2]<<7)&0x80))^(((in[3]>>1)&0x7F)^((in[3])&0x7F));
	out[4]='\0';
}

int checkUsrName(char *str)
{

	if ( strlen(str) < 4 || strlen(str) > 32)
	return 0;

	return 1; 
}


/*
 Do this before checking password and encrypting
 Check for at least one uppercase, one number. Assume the lowercase is present
*/
int checkChars(const char *str)
{
	int c=0, upper_c=0, lower_c=0, number_c=0;
	// move pointer to the password string
	//while (str[c++]!=' ');
	while (c < strlen(str))
	{
		if (str[c] >= 'a' && str[c] <= 'z')
			lower_c++;
		else if (str[c] >= 'A' && str[c] <= 'Z')
			upper_c++;
		else if (str[c] >= '0' && str[c] <= '9')
			number_c++;
		else
			return BAD_CHARS;	// Error: special character		
		//total_c++;	
		c++;	
	}
	// make the string shorter
	if (strlen(str) > MAX_PASSWD_LEN)
	{
		//str[12] = '\0'; 
		//printf("Truncated password: %s\n", str);
		return MAX_PASSWD_LEN;
		//return 1; //return 0;
	}	

	if (lower_c == 0 || upper_c == 0 || number_c == 0)
		return BAD_CHARS;
	
	return 1;
}

int chckUsr(char *str, FILE *file, FILE *newfile)
{
	char read_line[20]="", read_before[200]="";
	int alt=0; 

    while ((fscanf (file, "%s", read_line))!=EOF) 
	{
		// make a file copy up to the user's hashed password
		
		fprintf(newfile, "%s", read_line);
		
		//TO alternate between space and newline
		if (alt)
			fprintf(newfile, "\n");
		else
			fprintf(newfile, " ");
		alt = !alt;		

		 if (strcmp(read_line, str)==0)
		{
			printf("OK\n");
			return 1;
		}	
	}
	return 0;
}

// TODO: new method
void promptPasswd(char * password, int is_new_passwd){
    int bad_password = FALSE;
    int pass_count = 0;
	//char password[50];
	
    while(pass_count<3)
	{
		printf("Enter %sPassword: \n", is_new_passwd? "New " : "");
		// enter a new password
        bad_password = FALSE;
		scanf("%s", password);
		int ret = checkChars(password);
		if (ret == MAX_PASSWD_LEN)
		    password[MAX_PASSWD_LEN] = NULL_CHAR; 
		if (checkChars(password) == BAD_CHARS)
		{
			printf("ERROR: Password must contain at least one lower case, one upper case and one numerical character.\n");
			if (pass_count == 2)
				bad_password = TRUE;
			pass_count++;		// +
			continue; //exit(1);
		}	
		else break;
	}
	if (bad_password)
	{
	    // TODO: handle in main
		*password = NULL_CHAR; //exit(1);
	}
}

// TODO: MAIN
int main ()
{
	char user[100];
	char password[50];
	char hash[50];
	char get_hash[50];
	char junk[50];
	char read_line[50];
	int alt=0, 
		//pass_count = 0,
		bad_password = 0;
	FILE *file = fopen("pswd.txt", "a+");
	if(file == NULL)
	{
		perror("fopen");
		exit(1);
	}

	FILE *ff = fopen("pswd2.txt", "r+");
	if(ff == NULL)
	{
		perror("fopen");
		exit(1);
	}
	int ret;
	
	printf("Username:\n");
	scanf("%s",user);

	if (!checkUsrName(user)) 
	{
		printf("Restart program and choose a username 4-32 characters long \n");
		exit(1);
	}
	// If user exists
	if (chckUsr(user, file, ff)==1)
	{
	    //TODO: new call
		promptPasswd(password, FALSE);
		E(password, hash);
		fscanf (file, "%s", get_hash);	
		// authenticate
		 if (strcmp(hash, get_hash)==0)
		 {
			printf("Access Granted\n");
			// require password change
			printf("Enter new password:\n");
			strcpy(password, ""); // reset
			scanf("%s", password);
			E(password, hash);
			// write out new password
			fprintf(ff, "%s\n", hash);
			// continue reading to the end
			while ((fscanf (file, "%s", read_line))!=EOF)
			{
				fprintf(ff, "%s", read_line);
				if (alt)
					fprintf(ff, "\n");
				else
					fprintf(ff, " ");
				alt = !alt;			
			}
			// make a back up of original pswd file and 
			// copy new pswd file back to orig
			system("mv pswd.txt pswd.txt.bak");
			system("mv pswd2.txt pswd.txt");
			system("touch pswd2.txt");
			
		 }
		else
		{
			printf("Access Denied\n");
		}			
			
				
	}
	else
	{
		// check for password characters
		// TODO: add function call
		promptPasswd(password, TRUE);
		if (password == NULL)
		{
    		printf("Failed password attempts!\nExiting..\n");
    		exit(1);
		}
		E(password, hash);

		// now write this to the file
		if((fprintf(file, "%s %s\n", user, hash))==0)
			printf("ERROR: failed writing to file\n");
	}
	
	fclose(ff);
	fclose(file);	
	return 1;
}
