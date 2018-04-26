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
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.server.Connection;
import activitystreamer.util.Settings;

public class ClientSkeleton extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ClientSkeleton clientSolution;
	private TextFrame textFrame;
	private BufferedReader reader;
	private BufferedWriter writer;
	MessageListener ml;
	Socket socket = null;
	// added global variables
	private static String tempUsername;
	private static String tempSecret;
	
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
			socket = new Socket(Settings.getRemoteHostname(), Settings.getRemotePort()); // changed to use Settings variable instead of hardcoded ones	
			log.info("connected to port " + Settings.getRemotePort()); // changed to use log
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
	
	public boolean process(MessageListener ml, JSONObject message) {
		try {
			if(message.containsKey("command")) {
				
				// retrieve command to process
				String command = (String) message.get("command");
				
				switch (command) {
				
					// LOGIN_SUCCESS starts
				
					case "LOGIN_SUCCESS":
						if(message.containsKey("info")) {
							// set username and secret since server has authenticated them
							Settings.setUsername(tempUsername);
							Settings.setSecret(tempSecret);
							// print server message on console
							String loginSuccessInfo = (String) message.get("info");
							log.info(loginSuccessInfo);
						} else {
							// send invalid message if info is not found and close connection
							sendInvalidMessage("the received message did not contain a info");
							return true;
						}
						break;
				
					// LOGIN_SUCCESS ends
						
					// LOGIN_FAILED starts
						
					case "LOGIN_FAILED":
						if(message.containsKey("info")) {
							// print server message on console
							String loginFailedInfo = (String) message.get("info");
							log.info(loginFailedInfo);
						} else {
							// send invalid message if info is not found and close connection
							sendInvalidMessage("the received message did not contain a info");
							return true;
						}
						return true;
						
					// LOGIN_FAILED ends
						
					// REDIRECT starts
						
					case "REDIRECT":
						boolean hasHostname = message.containsKey("hostname");
						boolean hasPort = message.containsKey("port");
						
						if(hasHostname && hasPort) {
							// retrieve username and secret from Settings
							Settings.setRemoteHostname((String) message.get("hostname"));
							Settings.setRemotePort((int)(long) message.get("port"));
							// print to console
							log.info("redirecting to " + Settings.getRemotePort());
							// reconnect and login to new server
							executeRedirect();
						} else {
							if(!hasHostname) {
								sendInvalidMessage("the received message did not contain redirect server's hostname");
							} else if(!hasPort) {
								sendInvalidMessage("the received message did not contain redirect server's port number");
							}
						}
						break;
						
					// REDIRECT ends
						
					// REGISTER_FAILED starts
						
					case "REGISTER_FAILED":
						if(message.containsKey("info")) {
							// print server message on console
							String registerFailedInfo = (String) message.get("info");
							log.info(registerFailedInfo);
						} else {
							// send invalid message if info is not found and close connection
							sendInvalidMessage("the received message did not contain a info");
							return true;
						}
						break;
						
					// REGISTER_FAILED ends
						
					// REGISTER_SUCCESS starts
					
					case "REGISTER_SUCCESS":
						if(message.containsKey("info")) {
							// print server message on console
							String registerSuccessInfo = (String) message.get("info");
							log.info(registerSuccessInfo);
						} else {
							// send invalid message if info is not found and close connection
							sendInvalidMessage("the received message did not contain a info");
							return true;
						}
						break;
						
					// REGISTER_SUCCESS ends

					default:
						// if command is not valid send invalid message and close connection
						sendInvalidMessage("the received message did not contain a valid command");
						return true;
				}
			} else {
				// check if it's an activity object 
				if(!message.containsKey("authenticated_user")) {
					// send invalid message if command is not found and close connection
					sendInvalidMessage("the received message did not contain a command");
					return true;
				}
			}
		} catch (Exception e) {
			log.error("an error has occurred when processing the message" + e);
		}
		return false;
	}
	
	@SuppressWarnings("unchecked")
	public void sendActivityObject(JSONObject activityObj){
		try {
			writer.write(activityObj.toJSONString()+"\n");
			writer.flush();
			// get command to process requests
			// ADD: how to handle exception when it should be returned invalid message from server
			String command = (String) activityObj.get("command");
			switch(command) {
				case "LOGIN":
					tempUsername = (String) activityObj.get("username");
					tempSecret = (String) activityObj.get("secret");
					break;
				case "LOGOUT":
					// close connection
					socket.close();
					break;
				default:
					// nothing
					break;
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			JSONObject logoutMsg = new JSONObject();
			logoutMsg.put("Info","you are not connected to server, please exit");
		    getTextFrame().setOutputText(logoutMsg);
		    log.info("you are not connected to server, please exit");
			//e.printStackTrace();
		}
	}	
	
	@SuppressWarnings("unchecked")
	public void disconnect(){
//		JSONParser parser = new JSONParser();
//		JsonObject jobj = new JsonObject();
//		jobj =  (JsonObject) parser.parse("{\"command\" : \"LOGOUT\"}");
		try {
			writer.write("{\"command\" : \"LOGOUT\"}");
			writer.flush();
			socket.close();
		} catch (IOException e) {
			JSONObject logoutMsg = new JSONObject();
			logoutMsg.put("info", "you are not connected to server, please exit");
		    getTextFrame().setOutputText(logoutMsg);
			//e.printStackTrace();
		}
	}
	
	public TextFrame getTextFrame() {
		return textFrame;
	}

	public void setTextFrame(TextFrame textFrame) {
		this.textFrame = textFrame;
	}
	
	// added methods
	
	@SuppressWarnings("unchecked")
	private void sendInvalidMessage(String info) {
		//log.info("ACTIVITY: port " + Settings.getLocalPort() + " sending INVALID_MESSAGE to " + ml.getSocket().getLocalSocketAddress());
		JSONObject invalidMessage = new JSONObject();
		invalidMessage.put("command", "INVALID_MESSAGE");
		invalidMessage.put("info", info);
		// send message 
		sendActivityObject(invalidMessage);
	}
	
	@SuppressWarnings("unchecked")
	public void executeRedirect() {
		// close existing connection
		try {
			socket.close();
		} catch (IOException e) {
			log.error(e);
		}
		// create a new socket using the new remote hostname and port
		run();
		// ADD: then initiate login
		// Marshaling login parameters into JSON object
		JSONObject loginMessage = new JSONObject();
		loginMessage.put("command", "LOGIN");
		loginMessage.put("username", Settings.getUsername());
		loginMessage.put("secret", Settings.getSecret());
		sendActivityObject(loginMessage);
	}	
	
	public Socket getSocket() {
		return socket;
	}
}

