package activitystreamer.client;

// code is from tutorial 7
import java.io.BufferedReader;
import java.net.SocketAddress;
import java.net.SocketException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class MessageListener extends Thread {
	private static final Logger log = LogManager.getLogger();
	private boolean term=false;

	private BufferedReader reader;
	
	public MessageListener(BufferedReader reader) {
		this.reader = reader;
	}
	
	@Override
	public void run() {
		try {
			String msg = null;
			//Read messages from the server while the end of the stream is not reached
			while(!term && (msg = reader.readLine()) != null) {
				//Print the messages to the console
				JSONParser parser = new JSONParser();
				JSONObject newMessage = (JSONObject) parser.parse(msg);
				ClientSkeleton.getInstance().getTextFrame().setOutputText(newMessage);
				term = ClientSkeleton.getInstance().process(this, newMessage);
			}
			SocketAddress remoteSocketAddress = ClientSkeleton.getInstance().getSocket().getRemoteSocketAddress();
			ClientSkeleton.getInstance().getSocket().close();
			log.info("connection closed to " + remoteSocketAddress);
		} catch (SocketException e) {
			log.info("connection closed");
		} catch (Exception e) {
			e.printStackTrace();
		} 
		
	}
}
