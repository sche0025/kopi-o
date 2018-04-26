package activitystreamer.server;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Hashtable;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FileNotFoundException;
import java.io.BufferedReader;

import activitystreamer.util.Settings;

public class Control extends Thread {
	private static final Logger log = LogManager.getLogger();
	private static ArrayList<Connection> connections;
	private static boolean term=false;
	private static Listener listener;
	// added attributes
	private static Hashtable<String, Integer> serverLoad;
	private static Hashtable<String, JSONObject> serverRedirect;
	private static Hashtable<String, Connection> pendingRegistration;
	private static Hashtable<String, JSONObject> lockRequestResponses;
	private static JSONObject lockRequestResponseCount;
	
	protected static Control control = null;
	
	public static Control getInstance() {
		if(control==null){
			control=new Control();
		} 
		return control;
	}
	
	public Control() {
		
		// Initialisation:
		
		// connections array
		connections = new ArrayList<Connection>();
		// server's client load for load balancing
		serverLoad = new Hashtable<String, Integer>();
		// server's hostname and port number for redirection
		serverRedirect = new Hashtable<String, JSONObject>();
		// hashtable to store pending user registrations while awaiting server replies
		pendingRegistration =  new Hashtable<String, Connection>();
		// lock request responses - JSONObject to store number of responses and boolean (to allow or deny)
		lockRequestResponses = new Hashtable<String, JSONObject>();
		lockRequestResponseCount = new JSONObject();
		lockRequestResponseCount.put("count", 0);
		lockRequestResponseCount.put("allow", true);
		// create new password local storage if not created
		createUserLocalStorage();
		
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
				sendServerAuthentication(outgoingConnection(new Socket(Settings.getRemoteHostname(),Settings.getRemotePort())));
				
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
	@SuppressWarnings("unchecked")
	public synchronized boolean process(Connection con, String msg){
		try {
			// parser to convert a string into a JSONObject
			JSONParser parser = new JSONParser();
			JSONObject message = (JSONObject) parser.parse(msg);
			
			if(message.containsKey("command")) {
				
				// retrieve command to process
				String command = (String) message.get("command");
				
				switch (command) {
				
					// AUTHENTICATE starts
				
					case "AUTHENTICATE":
						
						if(message.containsKey("secret")) {
							//check secret between 2 connecting servers
							String authenticateSecret = (String) message.get("secret");
							// if the server has already been authenticated, send invalid message and close connection
							if(con.isServerAuthenticated() == true) {
								sendInvalidMessage(con, "server has already been authenticated");
								return true;
							}
							// if secret is incorrect, send AUTHENTICATION_FAIL and close connection
							else if (!Settings.getSecret().equals(authenticateSecret)) {
								log.info("authenticate failed with " + con.getSocket().getRemoteSocketAddress());
								sendAuthenticationFail(con, "the supplied secret is incorrect: " + authenticateSecret);
								return true;
							} 
							// if the secret is correct and the server has not been authenticated previously, 
							// indicate that the server is now authenticated and keep the connection open
							else {
								log.info("authenticate successfully with " + con.getSocket().getRemoteSocketAddress());
								con.setServerAuthenticated();
							}
						} else {
							// send invalid message if secret is not found and close connection
							sendInvalidMessage(con, "the received message did not contain a secret");
							return true;
						}
						break;
					
					// AUTHENTICATE ends
					
					// INVALID_MESSAGE starts
						
					case "INVALID_MESSAGE":
						
						if(message.containsKey("info")) {
							// retrieve invalid message info, print it, and close connection
							String invalidMessageInfo = (String) message.get("info");
							log.info(invalidMessageInfo);
							return true;						
						} else {
							// send invalid message if info is not found and close connection
							sendInvalidMessage(con, "the received message did not contain a info");
							return true;
						}
						
					// INVALID_MESSAGE ends
						
					// AUTHENTICATION_FAIL starts
						
					case "AUTHENTICATION_FAIL":
						
						if(message.containsKey("info")) {
							// retrieve authentication fail info, print it, and close connection
							String authenticationFailInfo = (String) message.get("info");
							log.info(authenticationFailInfo);
							return true;
						} else {
							// send invalid message if info is not found and close connection
							sendInvalidMessage(con, "the received message did not contain a info");
							return true;
						}
						
					// AUTHENTICATION_FAIL ends
						
					// LOGIN starts
						
					case "LOGIN":
						if(message.containsKey("username")) {
							String loginUsername = (String) message.get("username");
							// if username is not "anonymous" a secret must be given
							if(!loginUsername.equals("anonymous")) {
								if(message.containsKey("secret")) {
									String loginSecret = (String) message.get("secret");
									// authenticate client using given username and secret
									if (authenticateClient(loginUsername, loginSecret)) {
										// if username and secret matches in local storage, set client login username and secret (for activity message), and send LOGIN_SUCCESS message
										con.setClientUserName(loginUsername);
										con.setClientSecret(loginSecret);
										sendLoginSuccess(con, loginUsername);
										// then check server's client load versus the other connected servers
										// if server's logged in client load is 2 more than any other servers,
										// executeLoadBalance will redirect the client
										if (executeLoadBalance(con)) {
											// if redirecting client, close connection
											return true;
										}
									} 
									// if login failed, send LOGIN_FAIL message and close connection
									else {
										sendLoginFailed(con);
										return true;
									}
								} else {
									// send invalid message if username is not "anonymous" and a secret is not found, and close connection
									sendInvalidMessage(con, "the received message contained a non-anonymous username but did not contain a secret");
									return true;
								}
							} else {
								// set anonymous as username
								con.setClientUserName(loginUsername);
								sendLoginSuccess(con, loginUsername);
								if (executeLoadBalance(con)) {
									// if redirecting client, close connection
									return true;
								}
							}
						} else {
							// send invalid message if username is not found and close connection
							sendInvalidMessage(con, "the received message did not contain a username");
							return true;
						}
						break;
						
					// LOGIN ends
						
					// LOGOUT starts
						
					case "LOGOUT":
						// print client logged out message and close connection
						log.info("client " + con.getSocket().getRemoteSocketAddress() + " has logged out");
						return true;
						
					// LOGOUT ends
					
					// ACTIVITY_MESSAGE starts
						
					case "ACTIVITY_MESSAGE":
						// check if client has logged in
						if(con.isClient()) {
							// check if activity message contains username
							boolean hasUsername = message.containsKey("username");
							boolean hasSecret = message.containsKey("secret");
							boolean hasActivity = message.containsKey("activity");
							
							if(hasUsername) {
								String activityMessageUsername = (String) message.get("username");
								
								if(activityMessageUsername.equals("anonymous")) {
									if(hasActivity) {
										// process broadcast
										JSONObject activityMessageActivity = (JSONObject) message.get("activity");
										activityMessageActivity.put("authenticated_user", activityMessageUsername);
										sendActivityBroadcast(activityMessageActivity);
									} else {
										// respond with invalid message if message did not contain a activity and close the connection
										sendInvalidMessage(con, "the received message did not contain an activity object");
										return true;
									}
								} else if(!activityMessageUsername.equals("anonymous") && hasSecret) {
									String activityMessageSecret = (String) message.get("secret");
									if(activityMessageUsername.equals(con.getClientUserName()) && activityMessageSecret.equals(con.getClientSecret())) {
										if(hasActivity) {
											// process broadcast
											JSONObject activityMessageActivity = (JSONObject) message.get("activity");
											activityMessageActivity.put("authenticated_user", activityMessageUsername);
											sendActivityBroadcast(activityMessageActivity);
										} else {
											// respond with invalid message if message did not contain a activity and close the connection
											sendInvalidMessage(con, "the received message did not contain an activity object");
											return true;
										}
									} else {
										// send authentication fail if username or secret did not match
										sendAuthenticationFail(con, "username and secret do not match the logged in the user");
										return true;
									}
								} else {
									// respond with invalid message if message did not contain a secret and close the connection
									sendInvalidMessage(con, "the received message has a non-anonymous username but did not contain a secret");
									return true;
								}
							} else {
								// respond with invalid message if message did not contain a username and close the connection
								sendInvalidMessage(con, "the received message did not contain a username");
								return true;
							}
						} else {
							sendAuthenticationFail(con, "client not login");
						}
						break;
						
					// ACTIVITY_MESSAGE ends
						
					// SERVER_ANNOUNCE starts
						
					case "SERVER_ANNOUNCE":
						// check if server announce was received from unauthenticated server
						if (con.isServerAuthenticated()) {
							// check if server announce contains id, load, hostname, and port
							boolean hasID = message.containsKey("id");
							boolean hasLoad = message.containsKey("load");
							boolean hasHostname = message.containsKey("hostname");
							boolean hasPort = message.containsKey("port");
							
							if(hasID && hasLoad && hasHostname && hasPort) {
								// broadcast received server announce to every servers connected apart from originated server
								forwardServerMessage(con, message);
								// log that a server announce has been received
								String serverAnnounceId = (String) message.get("id");
								//log.info("received a SERVER_ANNOUNCE from " + con.getSocket().getRemoteSocketAddress());
								// update server information for load balancing
								int serverAnnouceIdLoad = (int)(long) message.get("load");
								serverLoad.put(serverAnnounceId, serverAnnouceIdLoad);
								serverRedirect.put(serverAnnounceId, message);
							} else {
								// respond with invalid message if any of the attributes were missing and close the connection
								if(!hasID) {
									sendInvalidMessage(con, "the received message did not contain a server id");
								} else if(!hasLoad) {
									sendInvalidMessage(con, "the received message did not contain server's client load count");
								} else if(!hasHostname) {
									sendInvalidMessage(con, "the received message did not contain server's hostname");
								} else if(!hasPort) {
									sendInvalidMessage(con, "the received message did not contain server's port number");
								}
								return true;
							}
						} else {
							// respond with invalid message if server has not been authenticated and close the connection
							sendInvalidMessage(con, "server has not been authenticated before sending server announce");
							return true;
						}
						break;
						
					// SERVER_ANNOUNCE ends
						
					// ACTIVITY_BROADCAST starts
					
					case "ACTIVITY_BROADCAST":
						if(message.containsKey("activity")) {
							JSONObject activityBroadcast = (JSONObject) message.get("activity");
							// broadcast activity broadcast message to all servers connected except the originated server
							forwardServerMessage(con, message);
							// send activity to all clients connected
							sendClientMessage(message);
						} else {
							// respond with invalid message if message did not contain a activity and close the connection
							sendInvalidMessage(con, "the received message did not contain an activity object");
							return true;
						}
						break;
						
					// ACTIVITY_BROADCAST ends
						
					// REGISTER starts
					
					case "REGISTER":
						// check if client has already logged in
						if(!con.isClient()) {
							// check if message contains username and secret
							boolean hasRegisterUsername = message.containsKey("username");
							boolean hasRegisterSecret = message.containsKey("secret");
							
							if(hasRegisterUsername && hasRegisterSecret) {
								String registerUsername = (String) message.get("username");
								String registerSecret = (String) message.get("secret");
								
								// check if username already exist in local storage
								if(checkUsernameExist(registerUsername)) {
									// send REGISTER_FAIL immediately if username was found in server's local storage and close connection
									sendRegisterFailed(con, registerUsername);
									return true;
								} else {
									// check how many servers are currently connected
									// if this is the only server, process and registration and indicate REGISTER_SUCCESS
									if(serverLoad.size() == 0) {
										storeUsernameSecret(registerUsername, registerSecret);
										sendRegisterSuccess(con, registerUsername);
									} 
									// if there were other servers connected, prepare to process lock request
									else {
										// store the username into a pendingRegistration hashtable to remember which client initiated the registration
										pendingRegistration.put(registerUsername, con);
										// store the lock request for each pending registration username in a lockRequestResponses hashtable 
										// initiate a JSONObject to remember the total count of responses and the boolean (to allow or deny)
										lockRequestResponseCount.put("count", 1);
										lockRequestResponseCount.put("allow", true); // true for lock allowed since username was not found in local storage
										lockRequestResponses.put(registerUsername, lockRequestResponseCount);
										// send lock_request to all other servers
										sendLockRequest(con, registerUsername, registerSecret);
										sendLockAllowed(registerUsername, registerSecret);
									}
								}
							} else {
								// respond with invalid message if any of the attributes were missing and close the connection
								if(!hasRegisterUsername) {
									sendInvalidMessage(con, "the received message did not contain a username");
								} else if(!hasRegisterSecret) {
									sendInvalidMessage(con, "the received message did not contain a secret");
								} 
								return true;
							}
						} else {
							// respond with invalid message if client has already logged in and close connection
							sendInvalidMessage(con, "client has already logged in");
							return true;
						}
						break;
						
					// REGISTER ends
						
					// LOCK_REQUEST starts
						
					case "LOCK_REQUEST":
						// check if lock request was received from unauthenticated server
						if (con.isServerAuthenticated()) {
							// check if message contains username and secret
							boolean hasLockRequestUsername = message.containsKey("username");
							boolean hasLockRequestSecret = message.containsKey("secret");
							
							if(hasLockRequestUsername && hasLockRequestSecret) {
								// broadcast lock request message to connected servers except the originated server
								forwardServerMessage(con, message);
								
								String lockRequestUsername = (String) message.get("username");
								String lockRequestSecret = (String) message.get("secret");

								// check if username already exist in local storage
								if(checkUsernameExist(lockRequestUsername)) {
									// store the lock request for each pending registration username in a lockRequestResponses hashtable 
									// initiate a JSONObject to remember the total count of responses and the boolean (to allow or deny)
									lockRequestResponseCount.put("count", 1);
									lockRequestResponseCount.put("allow", false); // false for lock denied since username was found in local storage
									lockRequestResponses.put(lockRequestUsername, lockRequestResponseCount);
									sendLockDenied(lockRequestUsername, lockRequestSecret);
								} else {
									// store the lock request for each pending registration username in a lockRequestResponses hashtable 
									// initiate a JSONObject to remember the total count of responses and the boolean (to allow or deny)
									lockRequestResponseCount.put("count", 1);
									lockRequestResponseCount.put("allow", true); // true for lock allowed since username was not found in local storage
									lockRequestResponses.put(lockRequestUsername, lockRequestResponseCount);
									sendLockAllowed(lockRequestUsername, lockRequestSecret);
								}
							} else {
								// respond with invalid message if any of the attributes were missing and close the connection
								if(!hasLockRequestUsername) {
									sendInvalidMessage(con, "the received message did not contain a username");
								} else if(!hasLockRequestSecret) {
									sendInvalidMessage(con, "the received message did not contain a secret");
								} 
								return true;
							}
						} else {
							// respond with invalid message if server has not been authenticated and close the connection
							sendInvalidMessage(con, "server has not been authenticated before sending lock request");
							return true;
						}
						break;
					
					// LOCK_REQUEST ends
						
					// LOCK_DENIED starts
						
					case "LOCK_DENIED":
						// check if lock request was received from unauthenticated server
						if (con.isServerAuthenticated()) {
							// check if message contains username and secret
							boolean hasLockDeniedUsername = message.containsKey("username");
							boolean hasLockDeniedSecret = message.containsKey("secret");
							
							if(hasLockDeniedUsername && hasLockDeniedSecret) {
								// broadcast lock request message to connected servers except the originated server
								forwardServerMessage(con, message);
								// update new server response to stored responses
								String lockDeniedUsername = (String) message.get("username");
								String lockDeniedSecret = (String) message.get("secret");
								lockRequestResponseCount = lockRequestResponses.get(lockDeniedUsername);
								// store count and allow into temporary variable for update
								int lockDeniedTempCount = (int) lockRequestResponseCount.get("count");
								boolean lockDeniedTempAllow = (boolean) lockRequestResponseCount.get("allow");
								// update new count and allow
								lockRequestResponseCount.replace("count", lockDeniedTempCount + 1);
								lockRequestResponseCount.replace("allow", lockDeniedTempAllow && false);
								
								// check if server had received all expected responses
								if((int)lockRequestResponseCount.get("count") == serverLoad.size() + 1) {
									if(pendingRegistration.get(lockDeniedUsername) != null) {
										// do not need to check responses because this is already a lock denied message
										// send REGISTER_FAIL to client via stored connection
										sendRegisterFailed(pendingRegistration.get(lockDeniedUsername), lockDeniedUsername);
										// remove the username from its local storage if the secret matches the associated secret in its local storage
										removeMatchedUsernameAndSecret(lockDeniedUsername, lockDeniedSecret);
										// clear content in hashtables to indicate register has been processed
										pendingRegistration.remove(lockDeniedUsername);
										lockRequestResponses.remove(lockDeniedUsername);
									} // else do nothing
								}
							} else {
								// respond with invalid message if any of the attributes were missing and close the connection
								if(!hasLockDeniedUsername) {
									sendInvalidMessage(con, "the received message did not contain a username");
								} else if(!hasLockDeniedSecret) {
									sendInvalidMessage(con, "the received message did not contain a secret");
								} 
								return true;
							}
						} else {
							// respond with invalid message if server has not been authenticated and close the connection
							sendInvalidMessage(con, "server has not been authenticated before sending lock request");
							return true;
						}
						break;
						
					// LOCK_DENIED ends
						
					// LOCK_ALLOWED starts
						
					case "LOCK_ALLOWED":
						// check if lock allowed was received from unauthenticated server
						if (con.isServerAuthenticated()) {
							// check if message contains username and secret
							boolean hasLockAllowedUsername = message.containsKey("username");
							boolean hasLockAllowedSecret = message.containsKey("secret");
							
							if(hasLockAllowedUsername && hasLockAllowedSecret) {
								// broadcast lock request message to connected servers except the originated server
								forwardServerMessage(con, message);
								// update new server response to stored responses
								String lockAllowedUsername = (String) message.get("username");
								String lockAllowedSecret = (String) message.get("secret");
								lockRequestResponseCount = lockRequestResponses.get(lockAllowedUsername);
								// store count and allow into temporary variable for update
								int lockAllowedTempCount = (int) lockRequestResponseCount.get("count");
								boolean lockAllowedTempAllow = (boolean) lockRequestResponseCount.get("allow");
								// update new count and allow
								lockRequestResponseCount.replace("count", lockAllowedTempCount + 1);
								lockRequestResponseCount.replace("allow", lockAllowedTempAllow && true);
								
								// check if server had received all expected responses
								if((int)lockRequestResponseCount.get("count") == serverLoad.size() + 1) {
									// if all responses were lock allowed
									if((boolean)lockRequestResponseCount.get("allow")) {
										// store username and secret in local storage
										storeUsernameSecret(lockAllowedUsername, lockAllowedSecret);
										if(pendingRegistration.get(lockAllowedUsername) != null) {
											// send REGISTER_SUCCESS to client via stored connection
											sendRegisterSuccess(pendingRegistration.get(lockAllowedUsername), lockAllowedUsername);
											// clear content in hashtables to indicate register has been processed
											pendingRegistration.remove(lockAllowedUsername);
											lockRequestResponses.remove(lockAllowedUsername);
										}
									// if there was even 1 lock denied
									} else {
										if(pendingRegistration.get(lockAllowedUsername) != null) {
											// send REGISTER_FAILED to client via stored connection
											sendRegisterFailed(pendingRegistration.get(lockAllowedUsername), lockAllowedUsername);
											// clear content in hashtables to indicate register has been processed
											pendingRegistration.remove(lockAllowedUsername);
											lockRequestResponses.remove(lockAllowedUsername);
										}
									}
								}
							} else {
								// respond with invalid message if any of the attributes were missing and close the connection
								if(!hasLockAllowedUsername) {
									sendInvalidMessage(con, "the received message did not contain a username");
								} else if(!hasLockAllowedSecret) {
									sendInvalidMessage(con, "the received message did not contain a secret");
								} 
								return true;
							}
						} else {
							// respond with invalid message if server has not been authenticated and close the connection
							sendInvalidMessage(con, "server has not been authenticated before sending lock allowed");
							return true;
						}
						break;
						
					// LOCK_ALLOWED ends
						
					default:
						// if command is not valid send invalid message and close connection
						sendInvalidMessage(con, "the received message did not contain a valid command");
						return true;
				}
				
			} else {
				// send invalid message if command is not found and close connection
				sendInvalidMessage(con, "the received message did not contain a command");
				return true;
			}
	
				
		} catch (ParseException e) {
			log.error("invalid json format, unable to parse in json object" + e);
		} catch (Exception e) {
			log.error("an error has occurred when processing the message" + e);
		}
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
			sendServerAnnounce(connections);
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
	
	// Invalid message
	
	@SuppressWarnings("unchecked")
	private void sendInvalidMessage(Connection c, String info) {
		log.info("ACTIVITY: port " + Settings.getLocalPort() + " sending INVALID_MESSAGE to " + c.getSocket().getLocalSocketAddress());
		// Marshaling
		JSONObject invalidMessage = new JSONObject();
		invalidMessage.put("command", "INVALID_MESSAGE");
		invalidMessage.put("info", info);
		// send message 
		if (c.writeMsg(invalidMessage.toJSONString())) {
			log.debug("[Port-" + Settings.getLocalPort() + "]: INVALID_MESSAGE sent to " + c.getSocket().getLocalSocketAddress());
		} else {
			log.info("[Port-" + Settings.getLocalPort() + "]: INVALID_MESSAGE sending to " + c.getSocket().getLocalSocketAddress() + " failed");
		}
	}
	
	// Server authenticate
	
	@SuppressWarnings("unchecked")
	private boolean sendServerAuthentication(Connection c) {
		JSONObject authenticate = new JSONObject();
		authenticate.put("command", "AUTHENTICATE");
		authenticate.put("secret", Settings.getSecret());
		// write message
		if (c.writeMsg(authenticate.toJSONString())) {
			log.debug("[Port-" + Settings.getLocalPort() + "]: AUTHENTICATE sent to Port-" + Settings.getRemotePort());
			return true;
		} else {
			log.debug("[Port-" + Settings.getLocalPort() + "]: AUTHENTICATE sending to Port-" + Settings.getRemotePort() + " failed");
			return false;
		}
	}
	
	@SuppressWarnings("unchecked")
	private boolean sendAuthenticationFail(Connection c, String info) {
		JSONObject failureMessage = new JSONObject();
		failureMessage.put("command", "AUTHENTICATION_FAIL");
		failureMessage.put("info", info);
		// write message
		if (c.writeMsg(failureMessage.toJSONString())) {
			log.debug("[Port-" + Settings.getLocalPort() + "]: AUTHENTICATE_FAIL sent to " + c.getSocket().getRemoteSocketAddress());
			return true;
		} else {
			log.debug("[Port-" + Settings.getLocalPort() + "]: AUTHENTICATE_FAIL sending to " + c.getSocket().getRemoteSocketAddress() + " failed");
			return false;
		}
	}
	
	// Server announce
	
	@SuppressWarnings("unchecked")
	private void sendServerAnnounce(ArrayList<Connection> allConnections) {
		JSONObject serverAnnounceMessage = new JSONObject();
		serverAnnounceMessage.put("command", "SERVER_ANNOUNCE");
		serverAnnounceMessage.put("id", Settings.getServerId());
		serverAnnounceMessage.put("load", getClientLoad());
		serverAnnounceMessage.put("hostname", Settings.getLocalHostname());
		serverAnnounceMessage.put("port", Settings.getLocalPort());
		// write message
		for(Connection c : allConnections) {
			// send serve announce to authenticated server
			if (c.isServerAuthenticated()) {
				if (c.writeMsg(serverAnnounceMessage.toJSONString())) {
					//log.debug("[Port-" + Settings.getLocalPort() + "]: SERVER_ANNOUNCE sent to " + c.getSocket().getRemoteSocketAddress());
				} else {
					//log.debug("[Port-" + Settings.getLocalPort() + "]: SERVER_ANNOUNCE sending to " + c.getSocket().getRemoteSocketAddress() + " failed");
				}
			}
		}
	}
	
	private void forwardServerMessage(Connection origin, JSONObject serverMessage) {
		for (Connection c : connections) {
			if (!c.equals(origin) && c.isServerAuthenticated()) {
				c.writeMsg(serverMessage.toJSONString());
			}
		}
	}
	
	private void sendClientMessage(JSONObject clientMessage) {
		for (Connection c : connections) {
			if (!c.isServerAuthenticated()) {
				c.writeMsg(clientMessage.toJSONString());
			}
		}
	}
	
	private int getClientLoad() {
		int load = 0;

		for(Connection c : connections) {
			if (c.isClient()) {
				load++;
			}
		}
		return load;
	}
	
	// Redirect
	
	private boolean executeLoadBalance(Connection c) {
		for (String serverId : serverLoad.keySet()) {
			// redirect if server finds any server with at least 2 clients lesser than its own
			if (getClientLoad() - serverLoad.get(serverId) >= 2) {
				// send destination server address									
				redirectClient(c, serverRedirect.get(serverId));
				return true;
			}
		}
		return false;
	}
	
	@SuppressWarnings("unchecked")
	private void redirectClient(Connection c, JSONObject address) {
		// Marshaling
		JSONObject redirectMessage = new JSONObject();
		redirectMessage.put("command", "REDIRECT");
		redirectMessage.put("hostname", address.get("hostname"));
		redirectMessage.put("port", address.get("port"));
		// write message to remote server as JSON object for authentication
		if (c.writeMsg(redirectMessage.toJSONString())) {
			log.debug("[Port-" + Settings.getLocalPort() + "]: REDIRECT sent to " + c.getSocket().getRemoteSocketAddress());
		} else {
			log.debug("[Port-" + Settings.getLocalPort() + "]: REDIRECT sending to " + c.getSocket().getRemoteSocketAddress() + " failed");
		}
	}
	
	// Login
	
	private boolean authenticateClient(String username, String secret) {
		boolean userAuthenticated = false;

		ArrayList<JSONObject> userLocalStorage = retrieveUserLocalStorage();	
		
		if (userLocalStorage.size() != 0) {
			for (JSONObject userInfo : userLocalStorage) {
				String storedUsername = (String) userInfo.get("username");
				String storedSecret = (String) userInfo.get("secret");
				if (storedUsername.equals(username) && storedSecret.equals(secret)) {
					userAuthenticated = true;
					log.debug("username: " + username + " and secret: " + secret + " authenticated");
					break;
				}
			}
		}
		return userAuthenticated;
	}
	
	@SuppressWarnings("unchecked")
	private void sendLoginSuccess(Connection c, String username) {
		// increase number of clients logged in on server
		c.setLoggedInClient();
		JSONObject loginSuccessMessage = new JSONObject();
		loginSuccessMessage.put("command", "LOGIN_SUCCESS");
		loginSuccessMessage.put("info", "logged in as user " + username);
		// write message to remote server as JSON object for authentication
		if (c.writeMsg(loginSuccessMessage.toJSONString())) {
			log.debug("[Port-" + Settings.getLocalPort() + "]: LOGIN_SUCCESS sent to " + c.getSocket().getRemoteSocketAddress());
		} else {
			log.debug("[Port-" + Settings.getLocalPort() + "]: LOGIN_SUCCESS sending to " + c.getSocket().getRemoteSocketAddress() + " failed");
		}
	}
	
	@SuppressWarnings("unchecked")
	private void sendLoginFailed(Connection c) {
		JSONObject loginFailedMessage = new JSONObject();
		loginFailedMessage.put("command", "LOGIN_FAILED");
		loginFailedMessage.put("info", "attempt to login with wrong secret");
		// write message to remote server as JSON object for authentication
		if (c.writeMsg(loginFailedMessage.toJSONString())) {
			log.debug("[Port-" + Settings.getLocalPort() + "]: LOGIN_FAILED sent to " + c.getSocket().getRemoteSocketAddress());
		} else {
			log.debug("[Port-" + Settings.getLocalPort() + "]: LOGIN_FAILED sending to " + c.getSocket().getRemoteSocketAddress() + " failed");
		}		
	}
	
	// Register
	
	private void createUserLocalStorage() {
		File passwordLocalStorage = new File("Port" + Settings.getLocalPort() + ".json");
		if(!(passwordLocalStorage.exists() && !passwordLocalStorage.isDirectory())) {
			try {
				passwordLocalStorage.createNewFile();
				log.debug("password local storage file created");
			} catch (Exception e) {
				log.debug("password local storage file could not be created " + e);
			}
		}
	}
	
	private ArrayList<JSONObject> retrieveUserLocalStorage() {
		ArrayList<JSONObject> allUserInfo = new ArrayList<JSONObject>();
		String filename = "Port" + Settings.getLocalPort() + ".json";
		try {
			// FileReader reads text file in the default encoding
			FileReader fileReader = new FileReader(filename);
			// wrap FileReader in BufferedReader
			BufferedReader bufferedReader = new BufferedReader(fileReader);
			
			String line = null;
			
			while((line = bufferedReader.readLine()) != null) {
				JSONObject userInfo = (JSONObject) new JSONParser().parse(line);
				allUserInfo.add(userInfo);
			}
			bufferedReader.close();
		} catch(FileNotFoundException e) {
			log.error("file " + filename + " do not exist");
		} catch(IOException e) {
			log.error("error reading " + filename);
		} catch(ParseException e) {
			log.error(e);
		}
		return allUserInfo;
	}
	
	private boolean checkUsernameExist(String username) {
		boolean usernameExist = false;

		ArrayList<JSONObject> userLocalStorage = retrieveUserLocalStorage();
		
		String requestedUsername = username;
		
		if (userLocalStorage.size() != 0) {
			for (JSONObject userInfo : userLocalStorage) {
				String storedUsername = (String) userInfo.get("username");
				if (storedUsername.equals(requestedUsername)) {
					usernameExist = true;
					break;
				}
			}
		}
		return usernameExist;	
	}
	
	private void removeMatchedUsernameAndSecret(String username, String secret) {
		ArrayList<JSONObject> userLocalStorage = retrieveUserLocalStorage();
		
		String requestedUsername = username;
		String requestedSecret = secret;
		
		if (userLocalStorage.size() != 0) {
			for (JSONObject userInfo : userLocalStorage) {
				String storedUsername = (String) userInfo.get("username");
				String storedSecret = (String) userInfo.get("secret");
				
				if (storedUsername.equals(requestedUsername) && storedSecret.equals(requestedSecret)) {
					userLocalStorage.remove(userInfo);
					log.debug("username: " + requestedUsername + " and secret: " + requestedSecret + " removed");
					break;
				}
			}
		}
	}
	
	@SuppressWarnings("unchecked")
	private void sendRegisterFailed(Connection c, String username) {
		JSONObject registerFailMessage = new JSONObject();
		registerFailMessage.put("command", "REGISTER_FAILED");
		registerFailMessage.put("info", username + " is already registered with the system");
		// reply to client
		if (c.writeMsg(registerFailMessage.toJSONString())) {
			log.debug("[Port-" + Settings.getLocalPort() + "]: REGISTER_FAILED sent to " + c.getSocket().getRemoteSocketAddress());
		} else {
			log.debug("[Port-" + Settings.getLocalPort() + "]: REGISTER_FAILED sending to " + c.getSocket().getRemoteSocketAddress() + " failed");
		}	
	}
	
	@SuppressWarnings("unchecked")
	private void sendRegisterSuccess(Connection c, String username) {
		JSONObject registerSuccessMessage = new JSONObject();
		registerSuccessMessage.put("command", "REGISTER_SUCCESS");
		registerSuccessMessage.put("info", "register success for " + username);
		// reply to client
		if (c.writeMsg(registerSuccessMessage.toJSONString())) {
			log.debug("[Port-" + Settings.getLocalPort() + "]: REGISTER_SUCCESS sent to " + c.getSocket().getRemoteSocketAddress());
		} else {
			log.debug("[Port-" + Settings.getLocalPort() + "]: REGISTER_SUCCESS sending to " + c.getSocket().getRemoteSocketAddress() + " failed");
		}	
	}
	
	@SuppressWarnings("unchecked")
	private void sendLockRequest(Connection c, String username, String secret) {
		JSONObject lockRequestMessage = new JSONObject();
		lockRequestMessage.put("command", "LOCK_REQUEST");
		lockRequestMessage.put("username", username);
		lockRequestMessage.put("secret", secret);
		// forward to other servers connected except the originated client
		forwardServerMessage(c, lockRequestMessage);
		log.debug("LOCK_REQUEST sent");
	}
	
	@SuppressWarnings("unchecked")
	private void sendLockAllowed(String username, String secret) {
		JSONObject lockAllowedMessage = new JSONObject();
		lockAllowedMessage.put("command", "LOCK_ALLOWED");
		lockAllowedMessage.put("username", username);
		lockAllowedMessage.put("secret", secret);
		
		for(Connection c : connections) {
			if(c.isServerAuthenticated()) {
				if (c.writeMsg(lockAllowedMessage.toJSONString())) {
					log.debug("[Port-" + Settings.getLocalPort() + "]: LOCK_ALLOWED sent to " + c.getSocket().getRemoteSocketAddress());
				} else {
					log.debug("[Port-" + Settings.getLocalPort() + "]: LOCK_ALLOWED sending to " + c.getSocket().getRemoteSocketAddress() + " failed");
				}
			}
		}
	}
	
	@SuppressWarnings("unchecked")
	private void sendLockDenied(String username, String secret) {
		JSONObject lockDeniedMessage = new JSONObject();
		lockDeniedMessage.put("command", "LOCK_DENIED");
		lockDeniedMessage.put("username", username);
		lockDeniedMessage.put("secret", secret);
		
		for(Connection c : connections) {
			if(c.isServerAuthenticated()) {
				if (c.writeMsg(lockDeniedMessage.toJSONString())) {
					log.debug("[Port-" + Settings.getLocalPort() + "]: LOCK_DENIED sent to " + c.getSocket().getRemoteSocketAddress());
				} else {
					log.debug("[Port-" + Settings.getLocalPort() + "]: LOCK_DENIED sending to " + c.getSocket().getRemoteSocketAddress() + " failed");
				}
			}
		}
	}
	
	@SuppressWarnings("unchecked")
	private void storeUsernameSecret(String username, String secret) {
		JSONObject newUser = new JSONObject();
		newUser.put("username", username);
		newUser.put("secret", secret);

		String filename = "Port" + Settings.getLocalPort() + ".json";

	    try {
	    	FileWriter file = new FileWriter(filename,true);
	    	file.write(newUser.toJSONString());
	    	file.write(System.lineSeparator());
	    	file.flush();
	    	file.close();
	    	log.info("username: " + username + " and secret: " + secret + " stored");
	    	
	    } catch (IOException e) {
	    	log.error("error storing username and secret " + e);
	    }
	}
	
	// Activity
	
	@SuppressWarnings("unchecked")
	private void sendActivityBroadcast(JSONObject activity) {
		JSONObject activityBroadcastMessage = new JSONObject();
		activityBroadcastMessage.put("command", "ACTIVITY_BROADCAST");
		activityBroadcastMessage.put("activity", activity);									
		// write message to all connections regardless of client or server
		for(Connection c : connections) {
			c.writeMsg(activityBroadcastMessage.toJSONString());
		}
	}
}
