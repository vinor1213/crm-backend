import { Request, Response } from "express";
import Permission from "./model";
import { AuthRequest } from "../../middlewares/auth";
import { createOrUpdatePermissionSchema } from "./permission.sanitize";

// 🟩 Create or update permission (Admin/User)
export const createOrUpdatePermission = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ success: false, message: "Not authorized" });
    }
    if (user.role !== "superadmin") {
      return res.status(403).json({ success: false, message: "Access denied. Superadmin only." });
    }

    // ✅ Validate request body
    const { error, value } = createOrUpdatePermissionSchema.validate(req.body, { allowUnknown: true });
    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details?.[0]?.message || "Invalid data format",
      });
    }

    const { instituteId, role, permissions } = value;

    // ✅ Check if a permission record already exists for this institute + role
    const existing = await Permission.findOne({ instituteId, role });

    let permissionDoc;
    if (existing) {
      existing.permissions = permissions;
      await existing.save();
      permissionDoc = existing;
    } else {
      permissionDoc = await Permission.create({
        instituteId,
        role,
        permissions,
      });
    }

    return res.status(200).json({
      success: true,
      message: existing
        ? "Permissions updated successfully ✅"
        : "Permissions created successfully ✅",
      data: permissionDoc,
    });
  } catch (error: any) {
    console.error("Error creating/updating permissions:", error);
    return res.status(500).json({
      success: false,
      message: "Server error while saving permissions",
      error: error.message,
    });
  }
};

// 🟦 Get permissions (by institute and/or role)
export const getPermissions = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ success: false, message: "Not authorized" });
    }

    if (user.role !== "superadmin") {
      return res.status(403).json({ success: false, message: "Access denied. Superadmin only." });
    }

    const { instituteId, role } = req.query;
    const filter: any = {};

    if (instituteId) filter.instituteId = instituteId;
    if (role) filter.role = role;

    const permissions = await Permission.find(filter).sort({ createdAt: -1 });

    return res.status(200).json({
      success: true,
      data: permissions,
    });
  } catch (error: any) {
    console.error("Error fetching permissions:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};


export const getPermissionsforusers = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ success: false, message: "Not authorized" });
    }

    const { instituteId, role } = req.query;
    const filter: any = {};

    if (instituteId) filter.instituteId = instituteId;
    if (role) filter.role = role;

    const permissions = await Permission.findOne(filter).sort({ createdAt: -1 });

    return res.status(200).json({
      success: true,
      data: permissions,
    });
  } catch (error: any) {
    console.error("Error fetching permissions:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

export const deletePermission = async (req: AuthRequest, res: Response) => {
  try {
    const { id } = req.params;

    const deleted = await Permission.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).json({ success: false, message: "Permission not found" });
    }

    return res.status(200).json({
      success: true,
      message: "Permission deleted successfully ✅",
    });
  } catch (error: any) {
    console.error("Error deleting permission:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};
