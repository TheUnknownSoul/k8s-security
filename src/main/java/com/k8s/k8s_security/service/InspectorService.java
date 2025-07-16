package com.k8s.k8s_security.service;

import com.k8s.k8s_security.exceptions.SomethingWentWrongException;
import com.k8s.k8s_security.styles.Color;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

/***
 * This service allow you to run few commands to investigate kubernetes image vulnerabilities, count severity in different
 * batch of files and gives info about each of them.

 @author Andrey Roy
 */

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

    public void runTrivyScan(String path) {
        if (path != null) {
            try {
                List<String> commands = Arrays.asList("sudo", "-S", "bash",
                        trivyScript.getFile().getAbsolutePath());
                ProcessBuilder pb = new ProcessBuilder(commands);
                pb.inheritIO();
                Process process = pb.start();


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
        if (path != null && !path.trim().isEmpty()) {

            Runtime runtime = Runtime.getRuntime();
            try {
                runtime.exec(String.format("python %s %s", cveCounter.getFile().getAbsoluteFile(), path));

            } catch (IOException e) {
                throw new SomethingWentWrongException(Color.RED.getColor() + " " + e.getMessage() + " " + Color.RESET.getColor());
            }
        }
    }

    public void runCveInfo(String path) {
        if (path != null && !path.trim().isEmpty()) {
            Runtime runtime = Runtime.getRuntime();
            try {
                runtime.exec(String.format("python " + cveInfo.getFile().getAbsoluteFile() + " %s", path));
            } catch (IOException e) {
                throw new SomethingWentWrongException(Color.RED.getColor() + " " + e.getMessage() + " " + Color.RESET.getColor());
            }
        }
    }

    public void runRbacCheck() {
        String currentDirectory = Paths.get("")
                .toAbsolutePath()
                .toString();
        File rolesFile = new File(currentDirectory + "/scan_files/roles.json");
        File roleBindingsFile = new File("/scan_files/rolebindings.json");
        File clusterRoleFile = new File("/scan_files/clusterroles.json");
        File clusterRoleBindings = new File("/scan_files/clusterrolebindings.json");

        if (rolesFile.exists() && roleBindingsFile.exists() && clusterRoleBindings.exists() && clusterRoleFile.exists()) {
            Runtime runtime = Runtime.getRuntime();
            try {
                runtime.exec(String.format("python " + rbacCheck.getFile().getAbsolutePath() + " %s"));
            } catch (IOException e) {
                System.err.println(e.getMessage());
            }
        } else {
            System.err.println("Can't find necessary files");
        }
    }
}
