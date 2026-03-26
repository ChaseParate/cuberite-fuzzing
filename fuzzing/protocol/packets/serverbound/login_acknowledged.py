from fuzzing.protocol.packets.serverbound import create_packet

# This doesn't have a wiki.vg page?


LOGIN_ACKNOWLEDGED = create_packet("Login Acknowledged", 0x3, None)
