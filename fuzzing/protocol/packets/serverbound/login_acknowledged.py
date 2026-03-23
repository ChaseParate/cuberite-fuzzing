from fuzzing.protocol.packets.serverbound import create_packet

# https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Acknowledged


LOGIN_ACKNOWLEDGED = create_packet("Login Acknowledged", 3, None)
