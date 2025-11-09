export {};

declare global {
  namespace Express {
    namespace Multer {
      interface File {
        /** Field name specified in the form */
        fieldname: string;
        /** Name of the file on the user's computer */
        originalname: string;
        /** Encoding type of the file */
        encoding: string;
        /** Mime type of the file */
        mimetype: string;
        /** Size of the file in bytes */
        size: number;
        /** Folder the file has been saved to */
        destination: string;
        /** Name of the file within the destination */
        filename: string;
        /** Location of the uploaded file */
        path: string;
        /** A Buffer of the entire file */
        buffer: Buffer;
        /** Readable stream of file contents */
        stream: NodeJS.ReadableStream;
      }
    }
  }
}
