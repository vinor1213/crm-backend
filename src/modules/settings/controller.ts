import { Request, Response } from 'express';
import { settingsSchema } from './settings.sanitize';

import Settings from './model';
// Create or update settings for an institute
export const upsertSettings = async (req: Request, res: Response) => {
  try {
    // Validate incoming data
    const { error } = settingsSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { instituteId } = req.body;

    // Check if a record already exists for this institute
    const existingSettings = await Settings.findOne({ instituteId });

    let settings;
    if (existingSettings) {
      // Update existing settings
      settings = await Settings.findOneAndUpdate(
        { instituteId },
        { $set: req.body },
        { new: true }
      );

      return res.status(200).json({
        success: true,
        message: 'Settings updated successfully',
        data: settings,
      });
    } else {
      // Create new settings
      settings = await Settings.create(req.body);

      return res.status(201).json({
        success: true,
        message: 'Settings created successfully',
        data: settings,
      });
    }
  } catch (err) {
    console.error('Error saving settings:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Get settings by institute ID
export const getSettingsByInstitute = async (req: Request, res: Response) => {
  try {
    const { instituteId } = req.params;
    const settings = await Settings.findOne({ instituteId });

    if (!settings) {
      return res.status(404).json({ message: 'Settings not found' });
    }

    res.status(200).json({
      success: true,
      data: settings,
    });
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Get all settings (optional admin endpoint)
export const getAllSettings = async (_req: Request, res: Response) => {
  try {
    const settings = await Settings.find().sort({ createdAt: -1 });
    res.status(200).json({ success: true, data: settings });
  } catch (error) {
    console.error('Error fetching all settings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Delete settings for a specific institute
export const deleteSettings = async (req: Request, res: Response) => {
  try {
    const { instituteId } = req.params;
    const deleted = await Settings.findOneAndDelete({ instituteId });

    if (!deleted) {
      return res.status(404).json({ message: 'Settings not found' });
    }

    res.status(200).json({
      success: true,
      message: 'Settings deleted successfully',
    });
  } catch (error) {
    console.error('Error deleting settings:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};
