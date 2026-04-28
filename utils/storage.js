const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const STORAGE_PATH = path.join(__dirname, '../data/reports.json');

/**
 * Ensures storage directory and file exist
 */
const initStorage = async () => {
    const dir = path.dirname(STORAGE_PATH);
    try {
        await fs.access(dir);
    } catch {
        await fs.mkdir(dir, { recursive: true });
    }

    try {
        await fs.access(STORAGE_PATH);
    } catch {
        await fs.writeFile(STORAGE_PATH, JSON.stringify([]));
    }
};

/**
 * Save a new report
 */
const saveReport = async (report) => {
    await initStorage();
    const data = await fs.readFile(STORAGE_PATH, 'utf-8');
    const reports = JSON.parse(data);
    
    const newReport = {
        id: uuidv4(),
        ...report
    };
    
    reports.unshift(newReport); // Add to beginning
    // Keep last 50 reports
    const limitedReports = reports.slice(0, 50);
    
    await fs.writeFile(STORAGE_PATH, JSON.stringify(limitedReports, null, 2));
    return newReport;
};

/**
 * Get all reports
 */
const getAllReports = async () => {
    await initStorage();
    const data = await fs.readFile(STORAGE_PATH, 'utf-8');
    return JSON.parse(data);
};

/**
 * Get report by ID
 */
const getReportById = async (id) => {
    const reports = await getAllReports();
    return reports.find(r => r.id === id);
};

/**
 * Delete report by ID
 */
const deleteReport = async (id) => {
    const reports = await getAllReports();
    const filtered = reports.filter(r => r.id !== id);
    await fs.writeFile(STORAGE_PATH, JSON.stringify(filtered, null, 2));
    return true;
};

module.exports = { saveReport, getAllReports, getReportById, deleteReport };
