import fs from "fs";
import path from "path";

/**
 * Creates a custom IOHandler that uses Node.js fs module
 * to save/load models compatible with TensorFlow.js
 * @param {string} modelDirPath - Absolute path to the directory to save/load the model
 */
export function getFileSystemHandler(modelDirPath) {
    const modelJsonPath = path.join(modelDirPath, "model.json");
    const weightsBinPath = path.join(modelDirPath, "weights.bin");

    return {
        save: async (modelArtifacts) => {
            const weightsManifest = [{
                paths: ["./weights.bin"],
                weights: modelArtifacts.weightSpecs
            }];

            const modelJSON = {
                modelTopology: modelArtifacts.modelTopology,
                format: modelArtifacts.format,
                generatedBy: modelArtifacts.generatedBy,
                convertedBy: modelArtifacts.convertedBy,
                weightsManifest
            };

            fs.mkdirSync(modelDirPath, { recursive: true });
            fs.writeFileSync(modelJsonPath, JSON.stringify(modelJSON, null, 2));

            // Save weights
            if (modelArtifacts.weightData) {
                const weightData = Buffer.from(modelArtifacts.weightData);
                fs.writeFileSync(weightsBinPath, weightData);
            }

            return {
                modelArtifactsInfo: {
                    dateSaved: new Date(),
                    modelTopologyType: "JSON",
                    modelTopologyBytes: JSON.stringify(modelJSON).length,
                    weightSpecsBytes: JSON.stringify(weightsManifest).length,
                    weightDataBytes: modelArtifacts.weightData ? modelArtifacts.weightData.byteLength : 0,
                }
            };
        },

        load: async () => {
            if (!fs.existsSync(modelJsonPath) || !fs.existsSync(weightsBinPath)) {
                throw new Error(`Model files not found in ${modelDirPath}`);
            }

            const modelJSON = JSON.parse(fs.readFileSync(modelJsonPath, "utf8"));
            const weightBuffer = fs.readFileSync(weightsBinPath);

            // Convert Buffer to ArrayBuffer
            const weightData = weightBuffer.buffer.slice(
                weightBuffer.byteOffset,
                weightBuffer.byteOffset + weightBuffer.byteLength
            );

            // Extract weight specs from the manifest
            // Typically there's one group. We flatten if multiple?
            // model.json usually has weightsManifest as array of groups.
            const weightSpecs = modelJSON.weightsManifest.flatMap(g => g.weights);

            return {
                modelTopology: modelJSON.modelTopology,
                format: modelJSON.format,
                generatedBy: modelJSON.generatedBy,
                convertedBy: modelJSON.convertedBy,
                weightsManifest: modelJSON.weightsManifest,
                weightSpecs: weightSpecs,
                weightData: weightData
            };
        }
    };
}
