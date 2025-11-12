import { Request, Response } from "express";
import Lead from "../lead/model";
import Application from "../applications/model";
import Institution from "../institutions/model";
import { AuthRequest } from "../../middlewares/auth";

export const dashboardData = async (req: AuthRequest, res: Response) => {
  try {
    const { startDate, endDate, instituteId } = req.query;
    const user = req.user;
 

    if (!user) return res.status(401).json({ message: "Not authorized" });

    // Initialize filters
    let leadFilter: any = {};
    let appFilter: any = {};

    // 🔹 Role-based access
    if (user.role === "superadmin") {
   
      if (instituteId && instituteId !== "all") {
        leadFilter.instituteId = instituteId;
        appFilter.instituteId = instituteId;
      }
    } else if (user.role === "admin") {
      leadFilter.instituteId = user.instituteId;
      appFilter.instituteId = user.instituteId;
    } else if (user.role === "user") {
      leadFilter = { instituteId: user.instituteId, createdBy: user.id };
      appFilter = { instituteId: user.instituteId, userId: user.id };
    }

    // 🔹 Date range (optional)
    if (startDate || endDate) {
      const dateFilter: any = {};
      if (startDate) {
        const start = new Date(startDate as string);
        start.setHours(0, 0, 0, 0);
        dateFilter.$gte = start;
      }
      if (endDate) {
        const end = new Date(endDate as string);
        end.setHours(23, 59, 59, 999);
        dateFilter.$lte = end;
      }
      leadFilter.createdAt = dateFilter;
      appFilter.createdAt = dateFilter;
    }

    // 🧮 Counts (using filters)
    const [totalInstitutes, totalLeads, totalApplications, paidApplications, unpaidApplications] =
      await Promise.all([
        Institution.countDocuments(),
        Lead.countDocuments(leadFilter),
        Application.countDocuments(appFilter),
        Application.countDocuments({ ...appFilter, paymentStatus: "Paid" }),
        Application.countDocuments({ ...appFilter, paymentStatus: "Unpaid" }),
      ]);

    // ✅ Send response
    res.status(200).json({
      success: true,
      message: "Dashboard data fetched successfully",
      data: {
        totalInstitutes,
        totalLeads,
        totalApplications,
        paidApplications,
        unpaidApplications,
      },
    });
  } catch (error: any) {
    console.error("❌ Dashboard Data Error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};

