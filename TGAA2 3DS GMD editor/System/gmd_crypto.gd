class_name GMDCrypto

# Llaves específicas para TGAA2 (DGS2) usando el KeyPair 1 del código original[cite: 1, 7]
const KEY1_STR: String = "e43bcc7fcab+a6c4ed22fcd433/9d2e6cb053fa462-463f3a446b19"
const KEY2_STR: String = "861f1dca05a0;9ddd5261e5dcc@6b438e6c.8ba7d71c*4fd11f3af1"

static func de_xor(input_data: PackedByteArray) -> PackedByteArray:
	var key1: PackedByteArray = KEY1_STR.to_ascii_buffer()
	var key2: PackedByteArray = KEY2_STR.to_ascii_buffer()
	var output: PackedByteArray = PackedByteArray()
	output.resize(input_data.size())
	
	for i in range(input_data.size()):
		var k1_byte = key1[i % key1.size()]
		var k2_byte = key2[i % key2.size()]
		output[i] = input_data[i] ^ k1_byte ^ k2_byte
		
	return output

# En TGAA2, la lógica de re-encriptación es idéntica a la de desencriptación para el KeyPair 1[cite: 1, 7]
static func re_xor(input_data: PackedByteArray) -> PackedByteArray:
	return de_xor(input_data)
