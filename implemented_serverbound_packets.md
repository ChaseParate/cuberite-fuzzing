# Implemented Serverbound Packets

## Handshake/Login
- [X] **[Handshake](https://c4k3.github.io/wiki.vg/Protocol.html#Handshake)** ([Implementation](fuzzing/protocol/packets/serverbound/handshake.py))
- [X] **[Login Start](https://c4k3.github.io/wiki.vg/Protocol.html#Login_Start)** ([Implementation](fuzzing/protocol/packets/serverbound/login_start.py))

## Play
- [X] **[Teleport Confirm](https://c4k3.github.io/wiki.vg/Protocol.html#Teleport_Confirm)** ([Implementation](fuzzing/protocol/packets/serverbound/teleport_confirm.py))
- [X] **[Tab-Complete](https://c4k3.github.io/wiki.vg/Protocol.html#Tab-Complete_.28serverbound.29)** ([Implementation](fuzzing/protocol/packets/serverbound/gameplay.py))
- [X] **[Chat Message](https://c4k3.github.io/wiki.vg/Protocol.html#Chat_Message_.28serverbound.29)** ([Implementation](fuzzing/protocol/packets/serverbound/chat_message.py))
- [X] **[Client Status](https://c4k3.github.io/wiki.vg/Protocol.html#Client_Status)** ([Implementation](fuzzing/protocol/packets/serverbound/client_status.py))
- [X] **[Client Settings](https://c4k3.github.io/wiki.vg/Protocol.html#Client_Settings)** ([Implementation](fuzzing/protocol/packets/serverbound/client_settings.py))
- [ ] **[Confirm Transaction](https://c4k3.github.io/wiki.vg/Protocol.html#Plugin_Message_.28serverbound.29:~:text=Player%20Position)**
- [ ] **[Enchant Item](https://c4k3.github.io/wiki.vg/Protocol.html#Enchant_Item)**
- [ ] **[Click Window](https://c4k3.github.io/wiki.vg/Protocol.html#Plugin_Message_.28serverbound.29:~:text=Player%20Position)**
- [ ] **[Close Window](https://c4k3.github.io/wiki.vg/Protocol.html#Plugin_Message_.28serverbound.29:~:text=Player%20Position)**
- [X] **[Plugin Message](https://c4k3.github.io/wiki.vg/Protocol.html#Plugin_Message_.28serverbound.29)** ([Implementation](fuzzing/protocol/packets/serverbound/gameplay.py))
- [ ] **[Use Entity](https://c4k3.github.io/wiki.vg/Protocol.html#Plugin_Message_.28serverbound.29)**
- [ ] **[Keep Alive](https://c4k3.github.io/wiki.vg/Protocol.html#Keep_Alive_.28serverbound.29)**
- [ ] **[Player](https://c4k3.github.io/wiki.vg/Protocol.html#Player)**
- [ ] **[Player Position](https://c4k3.github.io/wiki.vg/Protocol.html#Player_Position)**
- [X] **[Player Position and Look](https://c4k3.github.io/wiki.vg/Protocol.html#Player_Position_And_Look_.28serverbound.29)** ([Implementation](fuzzing/protocol/packets/serverbound/player_position_and_look.py))
- [ ] **[Player Look](https://c4k3.github.io/wiki.vg/Protocol.html#Player_Look)**
- [ ] **[Vehicle Move](https://c4k3.github.io/wiki.vg/Protocol.html#Vehicle_Move_.28serverbound.29)**
- [ ] **[Steer Boat](https://c4k3.github.io/wiki.vg/Protocol.html#Steer_Boat)**
- [ ] **[Craft Recipe Request](https://c4k3.github.io/wiki.vg/Protocol.html#Craft_Recipe_Request)**
- [ ] **[Player Abilities](https://c4k3.github.io/wiki.vg/Protocol.html#Player_Abilities_.28serverbound.29)**
- [X] **[Player Digging](https://c4k3.github.io/wiki.vg/Protocol.html#Player_Digging)** ([Implementation](fuzzing/protocol/packets/serverbound/player_digging.py))
- [ ] **[Entity Action](https://c4k3.github.io/wiki.vg/Protocol.html#Entity_Action)**
- [ ] **[Steer Vehicle](https://c4k3.github.io/wiki.vg/Protocol.html#Steer_Vehicle)**
- [ ] **[Crafting Book Data](https://c4k3.github.io/wiki.vg/Protocol.html#Crafting_Book_Data)**
- [ ] **[Resource Pack Status](https://c4k3.github.io/wiki.vg/Protocol.html#Resource_Pack_Status)**
- [ ] **[Advancement Tab](https://c4k3.github.io/wiki.vg/Protocol.html#Advancement_Tab)**
- [ ] **[Held Item Change](https://c4k3.github.io/wiki.vg/Protocol.html#Held_Item_Change_.28serverbound.29)**
- [ ] **[Creative Inventory Action](https://c4k3.github.io/wiki.vg/Protocol.html#Creative_Inventory_Action)**
- [ ] **[Update Sign](https://c4k3.github.io/wiki.vg/Protocol.html#Update_Sign)**
- [ ] **[Animation](https://c4k3.github.io/wiki.vg/Protocol.html#Animation_.28serverbound.29)**
- [ ] **[Spectate](https://c4k3.github.io/wiki.vg/Protocol.html#Spectate)**
- [ ] **[Player Block Placement](https://c4k3.github.io/wiki.vg/Protocol.html#Player_Block_Placement)**
- [X] **[Use Item](https://c4k3.github.io/wiki.vg/Protocol.html#Use_Item)** ([Implementation](fuzzing/protocol/packets/serverbound/use_item.py))
