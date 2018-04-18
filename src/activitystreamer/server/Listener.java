package activitystreamer.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import activitystreamer.util.Settings;

public class Listener extends Thread{
	private static final Logger log = LogManager.getLogger();
	private ServerSocket serverSocket=null;
	private boolean term = false;
	private int portnum;
	
	public Listener() throws IOException{
		portnum = Settings.getLocalPort(); // keep our own copy in case it changes later
		serverSocket = new ServerSocket(portnum);
		start();
	}
	
	@Override
	public void run() {
		log.info("listening for new connections on "+portnum);
		
		while(!term){
			Socket clientSocket;
			try {
				//Accept an incoming client/server connection request
				clientSocket = serverSocket.accept();

				//Create one thread per client/server connection, each thread will be
				//responsible for listening for messages from the client/server
				//and then 'handing' them to the control (coordinating singleton) to process them
				Control.getInstance().incomingConnection(clientSocket);
			} catch (IOException e) {
				log.info("received exception, shutting down");
				term=true;
			}
		}
	}

	public void setTerm(boolean term) {
		this.term = term;
		if(term) interrupt();
	}
	
	
}
