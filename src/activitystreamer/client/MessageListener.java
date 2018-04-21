package activitystreamer.client;

// code is from tutorial 7
import java.io.BufferedReader;
import java.net.SocketException;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

public class MessageListener extends Thread {

	private BufferedReader reader;
	
	public MessageListener(BufferedReader reader) {
		this.reader = reader;
	}
	
	@Override
	public void run() {
		try {
			String msg = null;
			//Read messages from the server while the end of the stream is not reached
			while((msg = reader.readLine()) != null) {
				//Print the messages to the console
				System.out.println("!!!:"+msg);
				JSONParser parser = new JSONParser();
				JSONObject newMessage = (JSONObject) parser.parse(msg);
				ClientSkeleton.getInstance().getTextFrame().setOutputText(newMessage);
				System.out.println("The server replied:" + msg);
			}
		} catch (SocketException e) {
			System.out.println("Socket closed because the user typed exit");
		} catch (Exception e) {
			e.printStackTrace();
		} 
		
	}
}
