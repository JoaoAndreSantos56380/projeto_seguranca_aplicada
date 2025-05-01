import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class MITM {

	private final int listenPort;
	private final String remoteHost;
	private final int remotePort;

	public MITM(int listenPort, String remoteHost, int remotePort) {
		this.listenPort = listenPort;
		this.remoteHost = remoteHost;
		this.remotePort = remotePort;
	}

	public void start() throws IOException {
		ServerSocket serverSocket = new ServerSocket(listenPort);
		System.out.printf("Proxy listening on port %d, forwarding to %s:%d%n",
				listenPort, remoteHost, remotePort);

		while (true) {
			Socket clientSocket = serverSocket.accept();
			Socket serverSocketToRemote = new Socket(remoteHost, remotePort);
			System.out.printf("Accepted connection from %s, connected to remote.%n", clientSocket.getRemoteSocketAddress());

			// Thread: client → server
			new Thread(() -> forwardData(clientSocket, serverSocketToRemote)).start();
			// Thread: server → client
			new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
		}
	}

	private void forwardData(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
				OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = in.read(buffer)) != -1) {
				out.write(buffer, 0, bytesRead);
				out.flush();
			}
		} catch (IOException e) {
			// Connection closed or error – terminate forwarding
		} finally {
			try {
				inputSocket.close();
			} catch (IOException ignored) {
			}
			try {
				outputSocket.close();
			} catch (IOException ignored) {
			}
		}
	}

	public static void main(String[] args) {
		if (args.length != 3) {
			System.err.println("Usage: java SimpleMITMProxy <listenPort> <remoteHost> <remotePort>");
			System.exit(1);
		}
		int listenPort = Integer.parseInt(args[0]);
		String remoteHost = args[1];
		int remotePort = Integer.parseInt(args[2]);

		try {
			new MITM(listenPort, remoteHost, remotePort).start();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
