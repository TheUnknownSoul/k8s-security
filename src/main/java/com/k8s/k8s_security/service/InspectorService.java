package com.k8s.k8s_security.service;

import com.k8s.k8s_security.exceptions.SomethingWentWrongException;
import com.k8s.k8s_security.styles.Color;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

@Service
public class InspectorService {

    @Value("classpath:scripts/CVE_counter.py")
    private Resource cveCounter;
    @Value("classpath:scripts/cve_info.py")
    private Resource cveInfo;
    @Value("classpath:scripts/rbac_check.py")
    private Resource rbacCheck;
    @Value("classpath:scripts/trivy_scan.sh")
    private Resource trivyScript;

    public void runTrivyScan(Path path, String sudoPassword) {
        if (path != null && sudoPassword != null) {
            try {

                List<String> commands = Arrays.asList("sudo", "-S", "bash", "-c",
                        trivyScript.getFile().getAbsolutePath());
                ProcessBuilder pb = new ProcessBuilder(commands);
                Process process = pb.start();

                // Write the password to sudo's stdin
                try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()))) {
                    writer.write(sudoPassword + "\n");
                    writer.flush();
                }

                // Read the output of the script
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\\n");
                    System.out.println(Color.BlUE.getColor() + output + Color.RESET.getColor());
                }
                reader.close();
                int exitCode = process.waitFor(); // Wait for the script to finish

                if (exitCode == 0) {
                    System.out.println(Color.GREEN.getColor() + "Script executed successfully with root privileges: " + Color.RESET.getColor());
                } else {
                    System.out.println(Color.RED.getColor() + "Script execution failed with exit code " + exitCode + " " + Color.RESET.getColor());
                }
            } catch (IOException | InterruptedException e) {
                throw new SomethingWentWrongException(Color.RED.getColor() + " " + e.getMessage() + " " + Color.RESET.getColor());

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
