package com.k8s.k8s_security.service;

import com.k8s.k8s_security.exceptions.SomethingWentWrongException;
import com.k8s.k8s_security.styles.Color;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Path;

@Service
public class InspectorService {

    @Value("classpath:scripts/CVE_counter.py")
    private Resource cveCounter;
    @Value("classpath:scripts/cve_info.py")
    private Resource cveInfo;

    public void runTrivyScan( Path path, String sudoPassword) {
        if (path != null) {
            try {

                ProcessBuilder pb = new ProcessBuilder("sudo", "-S", "bash", path.toString());
                pb.redirectErrorStream(true); // Redirect error stream to output stream

                Process process = pb.start();

                // Provide the sudo password to the process's input stream
                OutputStream os = process.getOutputStream();
                os.write((sudoPassword + "\\n").getBytes());
                os.flush();
                os.close();

                // Read the output of the script
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\\n");
                }

                int exitCode = process.waitFor(); // Wait for the script to finish

                if (exitCode == 0) {
                    System.out.println(Color.GREEN + "Script executed successfully with root privileges:\\n" + output + Color.RESET);
                } else {
                    System.out.println(Color.RED + "Script execution failed with exit code " + exitCode + ":\\n" + output + Color.RESET);
                }
            } catch (IOException e) {
                throw new SomethingWentWrongException(Color.RED.getColor() + " " + e.getMessage() + " " + Color.RESET.getColor());
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void runCveCounter(String path) {
        Runtime runtime = Runtime.getRuntime();
        try {
            runtime.exec(String.format("python %s %s", cveCounter.getFile().getAbsoluteFile(), path));

        } catch (IOException e) {
            throw new SomethingWentWrongException(Color.RED.getColor() + " " + e.getMessage() + " " + Color.RESET.getColor());
        }
    }

    public void runCveInfo(String path) {
        Runtime runtime = Runtime.getRuntime();
        try {
            runtime.exec(String.format("python " + cveInfo.getFile().getAbsoluteFile() + " %s", path));
        } catch (IOException e) {
            throw new SomethingWentWrongException(Color.RED.getColor() + " " + e.getMessage() + " " + Color.RESET.getColor());
        }

    }
}
