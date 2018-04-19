package activitystreamer.server;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.FileWriter;
import java.io.IOException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import activitystreamer.util.Settings;

public class Control extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ArrayList<Connection> connections;
	private static boolean term=false;
	private static Listener listener;
	
	protected static Control control = null;
	
	public static Control getInstance() {
		if(control==null){
			control=new Control();
		} 
		return control;
	}
	
	public Control() {
		
		// initialize the connections array
		connections = new ArrayList<Connection>();
		
		// start a listener
		try {
			// one main thread listening for incoming connection requests
			listener = new Listener();
			
		} catch (IOException e1) {
			log.fatal("failed to startup a listening thread: "+e1);
			System.exit(-1);
		}
		start();
	}
	
	public void initiateConnection() {
		
		// make a connection to another server if remote hostname is supplied
		if(Settings.getRemoteHostname()!=null){
			try {
				
				// initiate connection with remote host server (outgoing)
				// synchronise thread to organise server authentication - due to the lack of server id in JSON object
				// upon successful connection (i.e. socket accepted), begin server authentication by calling serverAuthentication() method
				serverAuthentication(outgoingConnection(new Socket(Settings.getRemoteHostname(),Settings.getRemotePort())));
				
			} catch (IOException e) {
				log.error("failed to make connection to "+Settings.getRemoteHostname()+":"+Settings.getRemotePort()+" :"+e);
				System.exit(-1);
			}
		}
	}
	
	/*
	 * Processing incoming messages from the connection.
	 * Return true if the connection should close.
	 */
	public synchronized boolean process(Connection con, String msg){
		try {
			
			// parser to convert a string into a JSONObject
			JSONParser parser = new JSONParser();
			JSONObject newMessage = (JSONObject) parser.parse(msg);
			
			// check for invalid message
			if (!isInvalidMessage(con, newMessage)) {

				// get command to process request
				String command = (String) newMessage.get("command");
				
				switch (command) {
				
					case "AUTHENTICATE":
						// retrieve value for secret
						String secret = (String) newMessage.get("secret");
						//check secret between 2 connecting servers
						if (!Settings.getSecret().equals(secret)) {
							// send AUTHENTICATION_FAIL
							authenticationFail(con, secret);
							// close connection
							return true;
						} 
						// invalid message can be handled in the parent invalid message check before switch/case
						//else return false
						else {
							// reply nothing to connected server
							// indicate that server has been authenticated
							con.setServerAuthenticated();
							// keep connection open
							log.info("AUTHENTICATE: hosting server port " + Settings.getLocalPort() + ": server authentication success!");
							return false;
						}
					case "INVALID_MESSAGE":
						String invalidMessageInfo = (String) newMessage.get("info");
						log.info(invalidMessageInfo);
						//then do smt, like close connect
						break;
					case "AUTHENTICATION_FAIL": // what if authentication fail was sent but not received? server announce will throw error
						// print info
						String authenticationFailInfo = (String) newMessage.get("info");
						log.info(authenticationFailInfo);
						// close connection with remote server
						return true;
					case "LOGIN":
						// do something
						// if login is successful
						if (true) {
							// increase the number of logged in clients first
							con.setLoggedInClient();
							// check server's client load versus the other connected servers
							// redirect if server finds any server with at least 2 clients lesser than its own
							//loadBalancer(connections);
						}
						break;
					case "LOGIN_SUCCESS":
						// do something
						break;
					case "REDIRECT":
						// check server announce
						break;
					case "LOGIN_FAILED":
						// do something
						break;
					case "LOGOUT":
						// do something
						break;
					case "ACTIVITY_MESSAGE":
						// do something
						break;
					case "SERVER_ANNOUNCE":
						// check if server announce was received from unauthenticated server
						if (con.isServerAuthenticated()) {
							// broadcast received server announce to every servers connected apart from originated server
							forwardServerAnnounce(con, newMessage);
							log.info(newMessage);
							return false;
						} else {
							// respond with invalid message
							sendInvalidMessage(con, "the server has not been authenticated");
						}
						
					case "ACTIVITY_BROADCAST":
						// do something
						break;
					case "REGISTER":
						// do something
						break;
					case "REGISTER_FAILED":
						// do something
						break;
					case "REGISTER_SUCCESS":
						// do something
						break;
					case "LOCK_REQUEST":
						// do something
						break;
					case "LOCK_DENIED":
						// do something
						break;
					case "LOCK_ALLOWED":
						// do something
						break;	
						
					default:
						// respond with invalid message
				}
			} else {
				// if invalid message is true close the connection
				return true;
			}
				
		} catch (Exception e) {
			e.printStackTrace();
		}

		//temporary
		return false;
	}
	
	/*
	 * The connection has been closed by the other party.
	 */
	public synchronized void connectionClosed(Connection con){
		if(!term) connections.remove(con);
	}
	
	/*
	 * A new incoming connection has been established, and a reference is returned to it
	 */
	public synchronized Connection incomingConnection(Socket s) throws IOException{
		log.debug("incoming connection: "+Settings.socketAddress(s));
		Connection c = new Connection(s);
		connections.add(c);
		return c;
	}
	
	/*
	 * A new outgoing connection has been established, and a reference is returned to it
	 */
	public synchronized Connection outgoingConnection(Socket s) throws IOException{
		log.debug("outgoing connection: "+Settings.socketAddress(s));
		Connection c = new Connection(s);
		connections.add(c);
		// always trust that parent server is authenticated until authentication fails
		// to include in report, security issues - because the parent server does not return authentication success until you send the next message, server unable to know
		// ALTERNATIVE: another way is to check next incoming message is not invalid message
		c.setServerAuthenticated();
		return c;
	}
	
	@Override
	public void run(){
		// establish thread for remote host server connection
		initiateConnection();
		log.info("using activity interval of "+Settings.getActivityInterval()+" milliseconds");
		
		while(!term){
			// do something with 5 second intervals in between
			// perform server announce every 5 seconds
			serverAnnounce(connections);
			try {
				Thread.sleep(Settings.getActivityInterval());
			} catch (InterruptedException e) {
				log.info("received an interrupt, system is shutting down");
				break;
			}
			if(!term){
				//log.debug("doing activity");
				term=doActivity();
			}
			
		}
		log.info("closing "+connections.size()+" connections");
		// clean up
		for(Connection connection : connections){
			connection.closeCon();
		}
		listener.setTerm(true);
	}
	
	public boolean doActivity(){
		return false;
	}
	
	public final void setTerm(boolean t){
		term=t;
	}
	
	public final ArrayList<Connection> getConnections() {
		return connections;
	}
	
	// added methods for project tasks
	
	private boolean isInvalidMessage(Connection c, JSONObject message) {
		// do something to check for message corruption
		// suggested ways to check, for each command, check that it strictly follows the given JSON format attributes
		// check username matches authenticated username etc.
		// return info on what's wrong
		// if it is invalid, send invalid message response using another method
		return false;
	}
	
	@SuppressWarnings("unchecked")
	private void sendInvalidMessage(Connection c, String info) {
		log.info("ACTIVITY: port " + Settings.getLocalPort() + " sending INVALID_MESSAGE to " + c.getSocket().getLocalSocketAddress());
		// Marshaling
		JSONObject invalidMessage = new JSONObject();
		invalidMessage.put("command", "INVALID_MESSAGE");
		invalidMessage.put("info", info);
		// send message 
		if (c.writeMsg(invalidMessage.toJSONString())) {
			log.info("INVALID_MESSAGE: INVALID_MESSAGE message sent successfully");
		} else {
			log.info("INVALID_MESSAGE: INVALID_MESSAGE message sending failed"); // what should we do if the invalid message keeps failing? loop sending and introduce a timeout?
		}
	}
	
	@SuppressWarnings("unchecked")
	private boolean serverAuthentication(Connection outConnection) {
		log.info("ACTIVITY: port " + Settings.getLocalPort() + " sending AUTHENTICATE to remote port " + Settings.getRemotePort());
		// Marshaling
		JSONObject authenticate = new JSONObject();
		authenticate.put("command", "AUTHENTICATE");
		authenticate.put("secret", Settings.getSecret());
		// write message to remote server as JSON object for authentication
		if (outConnection.writeMsg(authenticate.toJSONString())) {
			log.info("AUTHENTICATE: AUTHENTICATE message sent successfully");
			return true;
		} else {
			log.info("AUTHENTICATE: AUTHENTICATE message sending failed");
			return false;
		}
	}
	
	@SuppressWarnings("unchecked")
	private boolean authenticationFail(Connection outConnection, String incorrectSecret) {
		// Marshaling
		JSONObject failureMessage = new JSONObject();
		failureMessage.put("command", "AUTHENTICATION_FAIL");
		failureMessage.put("info", "the supplied secret is incorrect: " + incorrectSecret);
		// write message to connecting server as JSON object 
		if (outConnection.writeMsg(failureMessage.toJSONString())) {
			log.info("hosting server port " + Settings.getLocalPort() + ": authentication fail message sent successfully");
			return true;
		} else {
			log.debug("hosting server port " + Settings.getLocalPort() + ": authentication fail message sent failure");
			return false;
		}
	}
	
	@SuppressWarnings("unchecked")
	private void serverAnnounce(ArrayList<Connection> allConnections) {
		// Marshaling
		JSONObject serverAnnounceMessage = new JSONObject();
		serverAnnounceMessage.put("command", "SERVER_ANNOUNCE");
		serverAnnounceMessage.put("id", Settings.getServerId());
		serverAnnounceMessage.put("load", getClientLoad(allConnections));
		serverAnnounceMessage.put("hostname", Settings.getLocalHostname());
		serverAnnounceMessage.put("port", Settings.getLocalPort());
		// write message to all connecting servers as JSON object 
		for(Connection c : allConnections) {
			// ADD: if statement to check if connection is a client or server
			if (!c.isClient()) {
				if (c.writeMsg(serverAnnounceMessage.toJSONString())) {
					//log.info("server port " + Settings.getLocalPort() + ": SERVER_ANNOUNCE message sent successfully");
				} else {
					//log.debug("server port " + Settings.getLocalPort() + ": SERVER_ANNOUNCE message sending failed");
				}
			}
		}
	}
	
	private void forwardServerAnnounce(Connection origin, JSONObject serverAnnounceMessage) {
		for (Connection c : connections) {
			if (!c.equals(origin)) {
				c.writeMsg(serverAnnounceMessage.toJSONString());
			}
		}
	}
	
	private int getClientLoad(ArrayList<Connection> allConnections) {
		int load = 0;

		for(Connection c : allConnections) {
			if (c.isClient()) {
				load++;
			}
		}
		return load;
	}
	
//	private boolean loadBalancer(ArrayList<Connection> allConnections) {
//		int load = getClientLoad(allConnections);
//		
//		for(Connection c : allConnections) {
//			if (!c.isClient()) {
//				
//			}
//		}
//	}

}
