import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.results.ResultSinkInfo;
import soot.jimple.infoflow.results.ResultSourceInfo;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.*;
import soot.jimple.Stmt;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;

public class LeakChecker_v2 { 

    // Reserve 5 MB that can be released later
    private static byte[] reserve = new byte[96 * 1024 * 1024]; 

    static boolean outofMem_FLAG = false; 

    public static void main(String[] args) {

        String apkDir = "apks";
        String androidJar = "/home/vaibhav/Android/Sdk/platforms";
        String sourcesSinks = "SourcesAndSinks.txt";

        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String outputFile = "result_" + timestamp + ".json"; 
        
        try {
        
            Files.walk(Paths.get(apkDir))
                    .filter(p -> p.toString().endsWith(".apk"))
                    .forEach(apkPath -> {

                        JSONObject apkObject = new JSONObject();

                        try {
                            System.out.println("\n[*] Processing: " + apkPath.getFileName());

                            // Reset Soot
                            G.reset();

                            InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
                            config.getAnalysisFileConfig().setTargetAPKFile(apkPath.toFile());
                            config.getAnalysisFileConfig().setAndroidPlatformDir(new File(androidJar));
            
                            /* Removed in version 2.15.1; new ver. always assume/take as having Multiple-DexFiles */
                            // config.setMergeDexFiles(true); 

                            config.getCallbackConfig().setEnableCallbacks(false);
                            config.setFlowSensitiveAliasing(false);

                            // Enable path reconstruction
                            // config.setPathReconstructionMode(
                            //         InfoflowAndroidConfiguration.PathReconstructionMode.Fast
                            // );
                            config.getPathConfiguration().setPathReconstructionMode(
                                InfoflowAndroidConfiguration.PathReconstructionMode.NoPaths
                            );

                            config.setPathAgnosticResults(true);
                            soot.jimple.infoflow.android.resources.ARSCFileParser.STRICT_MODE = false;

                            config.setCallgraphAlgorithm(
                                    InfoflowAndroidConfiguration.CallgraphAlgorithm.CHA
                            );

                            ProcessManifest manifest = new ProcessManifest(apkPath.toString());

                            SetupApplication app = new SetupApplication(config);

                            System.out.println("[*] Running FlowDroid..."); 

                            InfoflowResults results = app.runInfoflow(new File(sourcesSinks));

                            apkObject.put("apk", apkPath.getFileName().toString());
                            apkObject.put("timestamp", timestamp);

                            JSONArray apkFlows = new JSONArray();

                            if (results != null && results.getResults() != null && !results.getResults().isEmpty()) {

                                // Build Unit -> Method map
                                System.out.println("Preparing output....");
                                Map<Unit, SootMethod> unitToMethod = new HashMap<>();

                                for (SootClass sc : Scene.v().getApplicationClasses()) {
                                    for (SootMethod sm : sc.getMethods()) {
                                        if (!sm.isConcrete()) continue;

                                        try {
                                            Body body = sm.retrieveActiveBody();
                                            for (Unit u : body.getUnits()) {
                                                unitToMethod.put(u, sm);
                                            }
                                        } catch (Exception ignored) {}
                                    }
                                }

                                Map<String, Boolean> exportedMap = new HashMap<>();

                                // Activities
                                for (soot.jimple.infoflow.android.manifest.binary.AbstractBinaryAndroidComponent act : manifest.getActivities()) {
                                    exportedMap.put(act.getNameString(), act.isExported());
                                }

                                // Services
                                for (soot.jimple.infoflow.android.manifest.binary.AbstractBinaryAndroidComponent srv : manifest.getServices()) {
                                    exportedMap.put(srv.getNameString(), srv.isExported());
                                }

                                // Receivers
                                for (soot.jimple.infoflow.android.manifest.binary.AbstractBinaryAndroidComponent rec : manifest.getBroadcastReceivers()) {
                                    exportedMap.put(rec.getNameString(), rec.isExported());
                                }

                                // Providers
                                for (soot.jimple.infoflow.android.manifest.binary.AbstractBinaryAndroidComponent prov : manifest.getContentProviders()) {
                                    exportedMap.put(prov.getNameString(), prov.isExported());
                                }


                                // Extract flows
                                for (ResultSinkInfo sink : results.getResults().keySet()) {

                                    Set<ResultSourceInfo> sources = results.getResults().get(sink);

                                    Stmt sinkStmt = sink.getStmt();
                                    SootMethod sinkMethod = unitToMethod.get(sinkStmt);

                                    if (sinkMethod == null) continue;

                                    String component = sinkMethod.getDeclaringClass().getName();
                                    boolean isExported = exportedMap.getOrDefault(component, false);

                                    for (ResultSourceInfo source : sources) {

                                        JSONObject flowObj = new JSONObject();

                                        flowObj.put("component", component);
                                        flowObj.put("source", source.getStmt().toString());
                                        flowObj.put("sink", sinkStmt.toString());
                                        flowObj.put("exported", isExported);

                                        // JSONArray pathArray = new JSONArray();

                                        // if (source.getPath() != null) {
                                        //     for (Stmt pathStmt : source.getPath()) {

                                        //         JSONObject step = new JSONObject();

                                        //         SootMethod m = unitToMethod.get(pathStmt);

                                        //         step.put("method", (m != null) ? m.getSignature() : "Unknown");
                                        //         step.put("stmt", pathStmt.toString());

                                        //         pathArray.put(step);
                                        //     }
                                        // }

                                        // flowObj.put("path", pathArray);
                                        apkFlows.put(flowObj);
                                    }
                                }
                            }

                            apkObject.put("flow_count", apkFlows.length());
                            apkObject.put("flows", apkFlows);
                            
                            System.out.println("[+] Done: " + apkPath.getFileName());

                        } 
                        catch (OutOfMemoryError | Exception e) { 

                            // Release reserved memory first (for OutOfMem Error)
                            reserve = null; 

                            System.out.println("\n[ERROR] " + e + "\n");

                            apkObject.put("apk", apkPath.getFileName().toString());
                            apkObject.put("error", "Processing failed");
                            apkObject.put("message", e.toString()); 

                            if(e.getClass().toString().equals("class java.lang.OutOfMemoryError")) { outofMem_FLAG = true; }
                            
                            System.out.println("[!] Failed: " + apkPath.getFileName() + "\n" + e);
                        }

                        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile, true))) {
                            writer.write(apkObject.toString(4));
                            // writer.write("\n");
                            writer.newLine(); 
                            writer.flush();
                        } catch (IOException e) {
                            e.printStackTrace();
                        } 

                        try 
                        { 
                            /* MOVE apk to diff. dir. if Failed due to OOM Error  
                            if(outofMem_FLAG) 
                            {
                                ...
                                ...
                                ...
                                System.out.println("[→] Moved to OutMemDir: " + apkPath.getFileName()); 

                                return; 
                            } */

                            Path doneDir = Paths.get("done", timestamp);
                            Files.createDirectories(doneDir); 

                            Path targetPath = doneDir.resolve(apkPath.getFileName());
                            Files.move(apkPath, targetPath, StandardCopyOption.REPLACE_EXISTING);

                            System.out.println("[→] Moved to done: " + apkPath.getFileName());
                        } catch (IOException e) {
                            System.out.println("[!] Failed to move: " + apkPath.getFileName());
                            e.printStackTrace();
                        }

                    });

			      System.out.println("\nResults saved to: " + outputFile); 
			      
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
