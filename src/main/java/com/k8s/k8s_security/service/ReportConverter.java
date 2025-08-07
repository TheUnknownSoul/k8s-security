package com.k8s.k8s_security.service;

import com.lowagie.text.Document;
import com.lowagie.text.Font;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfWriter;
import org.springframework.stereotype.Service;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.List;

@Service
public class ReportConverter {

    public void convertResultsToRDF(List<String> lines, String pdfPath) {
        try (Document document = new Document()) {

            PdfWriter.getInstance(document, new FileOutputStream(pdfPath));
            Font font = new Font(Font.COURIER, 12);
            document.open();
            for (String line : lines) {
                document.add(new Paragraph(line, font));
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
