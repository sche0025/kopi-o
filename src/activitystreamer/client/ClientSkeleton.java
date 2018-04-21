package activitystreamer.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.UnknownHostException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;

import activitystreamer.util.Settings;

public class ClientSkeleton extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSkeleton clientSolution;
	private TextFrame textFrame;
	private static String ip = "localhost";
	private static int port = 3780;
	private BufferedReader reader;
	private BufferedWriter writer;
	MessageListener ml;
	Socket socket = null;
	
	public static ClientSkeleton getInstance(){
		if(clientSolution==null){
			clientSolution = new ClientSkeleton();
		}
		return clientSolution;
	}
	
	public ClientSkeleton(){	
		start();
		textFrame = new TextFrame();
	}
	
	public void run() {
		try{
			System.out.println("connecting port:"+ Settings.getRemotePort());
			socket = new Socket(ip, Settings.getRemotePort());
			// Output and Input Stream
			reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
		    writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(),"UTF-8"));
		    ml = new MessageListener(reader);
		    ml.start(); 
		    
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			
		}	
	}
	
	public void interact() {	
//		Scanner sc;
//		String inputStr = null;
//		try {
//			sc = new Scanner(System.in);
//			while (!(inputStr = sc.nextLine()).equals("exit")) {
//				writer.write(inputStr+"\n");
//				writer.flush();
//			}
//			writer.write("exit");
//			writer.flush();
//			sc.close();
//			socket.close();
//		}catch(Exception e){
//			e.printStackTrace();
//			System.out.println("listen failed");
//		}
	}
	
	
	@SuppressWarnings("unchecked")
	public void sendActivityObject(JSONObject activityObj){
		try {
			writer.write(activityObj.toJSONString()+"\n");
			writer.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}	
	
	public void disconnect(){
//		JSONParser parser = new JSONParser();
//		JsonObject jobj = new JsonObject();
//		jobj =  (JsonObject) parser.parse("{\"command\" : \"LOGOUT\"}");
		try {
			writer.write("{\"command\" : \"LOGOUT\"}");
			writer.flush();
			socket.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public TextFrame getTextFrame() {
		return textFrame;
	}

	public void setTextFrame(TextFrame textFrame) {
		this.textFrame = textFrame;
	}
	

	
}
