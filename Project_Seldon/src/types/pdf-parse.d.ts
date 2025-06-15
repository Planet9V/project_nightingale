declare module 'pdf-parse' {
  interface PDFInfo {
    PDFFormatVersion: string;
    IsLinearized: boolean;
    IsAcroFormPresent: boolean;
    IsXFAPresent: boolean;
    Title?: string;
    Author?: string;
    Subject?: string;
    Keywords?: string;
    Creator?: string;
    Producer?: string;
    CreationDate?: string;
    ModDate?: string;
    Trapped?: string;
  }

  interface PDFMetadata {
    _metadata?: any;
    metadata?: any;
  }

  interface PDFData {
    numpages: number;
    numrender: number;
    info: PDFInfo;
    metadata: PDFMetadata;
    text: string;
    version: string;
  }

  interface PDFParseOptions {
    pagerender?: (pageData: any) => string;
    max?: number;
    version?: string;
  }

  function pdfParse(dataBuffer: Buffer, options?: PDFParseOptions): Promise<PDFData>;
  export = pdfParse;
}