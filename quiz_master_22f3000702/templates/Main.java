import java.util.*;

public class Main{
    public static void main(String[] args) {
        Scanner a1=new Scanner(System.in);
        String 
        int arr[]={10,20,30,40,50};
        int a=5;
        int k=2;
        int temp;
        for(int i=0; i<k; i++) {
            temp=arr[i];
            arr[i]=arr[a-k+i-1];
            arr[a-k+i-1]=temp;
        }
        for(int i=0;i<a;i++){
            System.out.println(arr[i]);
        }
    }
    
}