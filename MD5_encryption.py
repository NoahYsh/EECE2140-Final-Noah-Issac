def generate_md5_hash(file_path):
    """generate md5 hash of file"""
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def compare_hash(file_path, user_hash):
    """compare hash of file and user hash"""
    file_hash = generate_md5_hash(file_path)
    return file_hash == user_hash
