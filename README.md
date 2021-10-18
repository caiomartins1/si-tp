# XIUUU: Safe Sharing of Cryptographic Secrets -> CLI

CLI application to send cryptographic secrets between clients.
All clients connect to a server, from there they can choose to create a point-to-point connection between clients.

When connection beteween clients is created, from theres various actions can be performed.

Available:
  Diffie-Hellman
  Merkle Puzzle
  RSA
  
  simetric key exhange through previous agreed shared key.
  
  Secret messages exchange by using the shared key
  Use of of signature for messages(available when using RSA)
