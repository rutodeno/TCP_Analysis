#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX 178200

void tcpAnalysis(char *in_filename, char *out_filename) {
    FILE *fp_in, *fp_out;
    char *filecontent;
    unsigned int fsize = 0;
    char arrayChar[MAX];
    /*
    The range of the downloaded file size is from around 100KB to 2 Mbytes. You should ignore the TCP sessions show less than 100 KB size in total transmission if exist.
    The analysis for all targeted TCP sessions and report following information 
    • Download time (sec)
    • Downloaded File size (Bytes)
    • Throughput 
    • Packet loss rate
    • RTT (round trip time)
    */



    fp_in = fopen(in_filename,"r");
    if (fp_in < 0) {
        perror("Unable to open trace file\n");
        exit(1);
    } 
    
    
    fp_out = fopen(out_filename, "w");

    if (fp_out < 0) {
        perror("unable to write to requiredData.txt\n");
        exit(1);
    }
    
    fseek(fp_in, 0, SEEK_END);
    fsize = ftell(fp_in);
    fseek(fp_in, 0, SEEK_SET);
    filecontent = (char*)malloc(fsize + 1);
    
    /*

    while (1) {
        

        if (fgets(filecontent, fsize, fp_in) == NULL) {

            if (feof(fp_in)) {
                printf("End of file\n");
                break;
            } else {
                perror("issue !! oops");
                break;
            }

        } else {
            fscanf(fp_in, );          

        }      

    }

    */
   int throughput_value = 0;
   while (fscanf(fp_in, "throughput: %d", &throughput_value) != EOF) {
       printf("%d", throughput_value);
   }
    
    //free(filecontent);

    printf("Yes, cooking with gasoline\n");
    fclose(fp_in);
    fclose(fp_out);
}


int main(int argc, char* argv[]) {
    
    printf("Selected Option: %s\n", argv[1]);

    if (strcmp(argv[1], "tcpAnalysis") == 0) {
        tcpAnalysis(argv[2], argv[3]);
    }else{
        printf("try again\n");
    }
    return 0;

}
