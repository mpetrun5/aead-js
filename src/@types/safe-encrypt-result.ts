import {Buffer} from "buffer";

export interface IEncryptResult {
  cipher: Buffer;
  mac: Buffer;
}
