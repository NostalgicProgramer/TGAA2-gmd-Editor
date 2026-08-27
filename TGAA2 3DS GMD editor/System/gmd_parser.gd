class_name GMDParser

class GMDContentData:
	var name: String
	var entries: Array[Dictionary] = [] # Almacenará diccionarios con "label" y "text"

# Helper para leer strings terminadas en nulo (CString)
static func read_c_string(file: FileAccess) -> String:
	var bytes: PackedByteArray = PackedByteArray()
	var b = file.get_8()
	while b != 0:
		bytes.append(b)
		b = file.get_8()
	return bytes.get_string_from_ascii()

# Carga de GMDv2 CTR (3DS)
static func load_gmd(filepath: String) -> GMDContentData:
	var file = FileAccess.open(filepath, FileAccess.READ)
	file.set_big_endian(false)
	
	var data = GMDContentData.new()
	
	# Header
	var magic = file.get_buffer(4).get_string_from_ascii()
	var version = file.get_32()
	var language = file.get_32()
	var zero1 = file.get_64()
	var label_count = file.get_32()
	var section_count = file.get_32()
	var label_size = file.get_32()
	var section_size = file.get_32()
	var name_size = file.get_32()
	
	data.name = read_c_string(file)
	
	var label_entries = []
	for i in range(label_count):
		label_entries.append({
			"section_id": file.get_32(),
			"hash1": file.get_32(),
			"hash2": file.get_32(),
			"label_offset": file.get_32(),
			"list_link": file.get_32()
		})
		
	# BucketList para CTR
	var buckets = []
	if label_count > 0:
		for i in range(0x100):
			buckets.append(file.get_32())
			
	var label_data_offset = file.get_position()
	
	# Leer y desencriptar el bloque de texto
	file.seek(0x28 + (name_size + 1) + (label_count * 0x14 + (0x100 * 0x4 if label_count > 0 else 0)) + label_size)
	var encrypted_text = file.get_buffer(section_size)
	var decrypted_text = GMDCrypto.de_xor(encrypted_text)
	
	# Parsear secciones de texto
	var text_offset = 0
	for i in range(section_count):
		var text_end = text_offset
		while text_end < decrypted_text.size() and decrypted_text[text_end] != 0:
			text_end += 1
			
		var section_bytes = decrypted_text.slice(text_offset, text_end)
		var text_string = section_bytes.get_string_from_utf8()
		
		if text_string != null:
			text_string = text_string.replace("\n", "\r\n")
		else:
			print("Error: Los bytes de la sección ", i, " no son texto UTF-8 válido.")
			text_string = ""
			
		text_offset = text_end + 1
		
		var label_name = "no_name_%03d" % i
		for entry in label_entries:
			if entry.section_id == i:
				var bk = file.get_position()
				file.seek(label_data_offset + entry.label_offset)
				label_name = read_c_string(file)
				file.seek(bk)
				break
				
		data.entries.append({
			"label": label_name,
			"text": text_string
		})
		
	file.close()
	return data

# Guardado de GMDv2 CTR (3DS) - Estructura fiel a C#
static func save_gmd(filepath: String, data: GMDContentData):
	var file = FileAccess.open(filepath, FileAccess.WRITE)
	file.set_big_endian(false)
	
	# 1. Preparar Text Blob (Corregido el doble salto de línea)
	var text_blob_bytes = PackedByteArray()
	for entry in data.entries:
		var text_str = entry.text.replace("\r\n", "\n")
		text_blob_bytes.append_array(text_str.to_utf8_buffer())
		text_blob_bytes.append(0)
		
	# Encriptación (Asegúrate de que re_xor use las llaves de DGS2 internamente)
	var encrypted_text = GMDCrypto.re_xor(text_blob_bytes)
	
	# 2. Preparar Label Blob
	var label_blob_bytes = PackedByteArray()
	var real_label_count = 0
	for entry in data.entries:
		if not entry.label.begins_with("no_name"):
			label_blob_bytes.append_array(entry.label.to_ascii_buffer())
			label_blob_bytes.append(0)
			real_label_count += 1
			
	# 3. Preparar Label Entries y Buckets
	var label_entries = []
	var buckets_dict = {}
	var current_label_offset = 0
	var counter = 0
	
	for i in range(data.entries.size()):
		var lbl = data.entries[i].label
		
		if not lbl.begins_with("no_name"):
			var hash1 = (~GMDCRC32.create_hash(lbl + lbl)) & 0xFFFFFFFF
			var hash2 = (~GMDCRC32.create_hash(lbl + lbl + lbl)) & 0xFFFFFFFF
			
			label_entries.append({
				"section_id": i,
				"hash1": hash1,
				"hash2": hash2,
				"label_offset": current_label_offset,
				"list_link": 0
			})
			current_label_offset += lbl.length() + 1
			
			var bucket = ((~GMDCRC32.create_hash(lbl)) & 0xFFFFFFFF) & 0xFF
			if buckets_dict.has(bucket):
				label_entries[buckets_dict[bucket]].list_link = counter
				buckets_dict[bucket] = counter
			else:
				buckets_dict[bucket] = counter
				
			counter += 1
			
	# 4. Construir Bucket Blob
	var bucket_blob = []
	bucket_blob.resize(0x100)
	bucket_blob.fill(0)
	
	if real_label_count > 0:
		var counter2 = 0
		for i in range(data.entries.size()):
			var lbl = data.entries[i].label
			if not lbl.begins_with("no_name"):
				var bucket = ((~GMDCRC32.create_hash(lbl)) & 0xFFFFFFFF) & 0xFF
				if bucket_blob[bucket] == 0:
					bucket_blob[bucket] = -1 if counter2 == 0 else counter2
				counter2 += 1
				
	# 5. Escribir Header
	file.store_buffer(PackedByteArray([0x47, 0x4D, 0x44, 0x00]))
	file.store_32(0x00010302)
	file.store_32(1)
	file.store_64(0)
	file.store_32(real_label_count)
	file.store_32(data.entries.size())
	file.store_32(label_blob_bytes.size())
	file.store_32(encrypted_text.size())
	file.store_32(data.name.length())
	
	file.store_buffer(data.name.to_ascii_buffer())
	file.store_8(0)
	
	for e in label_entries:
		file.store_32(e.section_id)
		file.store_32(e.hash1)
		file.store_32(e.hash2)
		file.store_32(e.label_offset)
		file.store_32(e.list_link)
		
	if real_label_count > 0:
		for b in bucket_blob:
			file.store_32(b)
			
	file.store_buffer(label_blob_bytes)
	file.store_buffer(encrypted_text)
	
	file.close()
