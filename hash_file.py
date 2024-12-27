import hashlib

def hash_file_birdcipher(filename, algorithm):
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.file_digest(f, algorithm).hexdigest()


#print(hash_file_birdcipher('C:/Users/GEOVANNY/Documents/Nueva carpeta/API key.docx'))