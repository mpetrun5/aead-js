import {Buffer} from "buffer";

export interface EncryptResult {
    cipher: Buffer,
    mac: Buffer
}
