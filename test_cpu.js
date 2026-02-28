import si from 'systeminformation';

console.log("Testing CPU Load retrieval...");
try {
    const data = await si.currentLoad();
    console.log("Raw CPU Data:", JSON.stringify(data, null, 2));
    console.log("Current Load:", data.currentload);
} catch (error) {
    console.error("Error:", error);
}
