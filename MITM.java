import java.io.InputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public class MITM {

	private final int listenPort;
	private final String remoteHost;
	private final int remotePort;
	private final String op;

	public MITM(int listenPort, String remoteHost, int remotePort, String op) {
		this.listenPort = listenPort;
		this.remoteHost = remoteHost;
		this.remotePort = remotePort;
		this.op = op;
	}

	public void start() throws IOException {
		ServerSocket serverSocket = new ServerSocket(listenPort);
		System.out.printf("Proxy listening on port %d, forwarding to %s:%d%n",
				listenPort, remoteHost, remotePort);

		while (true) {
			Socket clientSocket = serverSocket.accept();
			Socket serverSocketToRemote = new Socket(remoteHost, remotePort);
			System.out.printf("Accepted connection from %s, connected to remote.%n", clientSocket.getRemoteSocketAddress());

			switch (op) {
				case "r":  // Replay attack
					System.out.printf("Initiating Replay Attack \n");
					new Thread(() -> replayAttack(clientSocket, serverSocketToRemote)).start();
					new Thread(() -> replayAttack(serverSocketToRemote, clientSocket)).start();
					break;

				case "t":  // Timeout attack
					System.out.printf("Initiating Timeout Attack \n");
					//new Thread(() -> timeoutAttack(clientSocket, serverSocketToRemote)).start();
					//new Thread(() -> timeoutAttack(serverSocketToRemote, clientSocket)).start();
					break;

				case "d":  // Timeout attack
					System.out.printf("Initiating Drop Attack \n");
					new Thread(() -> forwardData(clientSocket, serverSocketToRemote)).start();
					new Thread(() -> byteFlip(serverSocketToRemote, clientSocket)).start();
					break;

				case "p":  // Timeout attack
					System.out.printf("Initiating Print Size of Packets \n");
					new Thread(() -> forwardDataSize(clientSocket, serverSocketToRemote)).start();
					new Thread(() -> forwardDataSize(serverSocketToRemote, clientSocket)).start();
					break;

				default:   // Normal forward
					new Thread(() -> forwardData(clientSocket, serverSocketToRemote)).start();
					new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
					break;
			}
		}
	}

	private void forwardData(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
				OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = in.read(buffer)) != -1) {
				out.write(buffer, 0, bytesRead);
				//System.out.println(Arrays.toString(buffer));
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

	private void forwardDataSize(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
			 OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = in.read(buffer)) != -1) {

				out.write(buffer, 0, bytesRead);
				//System.out.println(Arrays.toString(buffer));
				out.flush();

				if (buffer[0] == 109 && buffer[1] == 58) {
					//System.out.println(Arrays.toString(buffer));
					System.out.println(bytesRead);
				}
			}

		} catch (IOException e) {
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

	private void byteFlip(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
			 OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			int count = 0;
			byte[] delayedPacket;
			while ((bytesRead = in.read(buffer)) != -1) {
				if (count != 0) {
					out.write(buffer, 0, bytesRead);
					//System.out.println(Arrays.toString(buffer));
					out.flush();
				} else {
					delayedPacket = new byte[bytesRead];
					System.arraycopy(buffer, 0, delayedPacket, 0, bytesRead);
					delayedPacket[2] = (byte) 560;
					//System.out.println(Arrays.toString(delayedPacket));
					out.write(delayedPacket, 0, bytesRead);
					out.flush();
				}
				count++;

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

	private void replayAttack(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
			 OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			int n = 2; //num of replays
			while ((bytesRead = in.read(buffer)) != -1) {
				for(int i = 0; i < n; i++) {
					out.write(buffer, 0, bytesRead);
					out.flush();
				}
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
	private void timeoutAttack(int seconds){
		System.out.println("Sleeping for " + seconds + " seconds via TimeUnit...");
		try {
			TimeUnit.SECONDS.sleep(seconds); // sleeps for 11 seconds
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt(); // restore interrupt status
			System.err.println("Sleep was interrupted");
		}
		System.out.println("Done sleeping!");
	}

	public static void main(String[] args) {
		if (args.length != 4) {
			System.err.println("Usage: java SimpleMITMProxy <listenPort> <remoteHost> <remotePort> <operation>");
			System.exit(1);
		}
		int listenPort = Integer.parseInt(args[0]);
		String remoteHost = args[1];
		int remotePort = Integer.parseInt(args[2]);

		try {
			new MITM(listenPort, remoteHost, remotePort, args[3]).start();
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.exit(0);
	}
}
