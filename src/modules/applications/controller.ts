import { Request, Response } from 'express'
import Application from './model'
import { createApplicationSchema } from './application.sanitize'
import { AuthRequest } from '../../middlewares/auth'
import FormManager from '../form-manage/model'
import LeadModel from '../lead/model'

// 🧾 Create Application
const SibApiV3Sdk = require('sib-api-v3-sdk');

const defaultClient = SibApiV3Sdk.ApiClient.instance;
defaultClient.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;
const emailApi = new SibApiV3Sdk.TransactionalEmailsApi();


export const sendmail = async (req: Request, res: Response) => {
  try {
    const { toEmail, toName, subject, htmlContent } = req.body;

    if (!toEmail || !subject || !htmlContent) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields: toEmail, subject, htmlContent",
      });
    }

    const emailData = {
      sender: { email: "vinor1213@gmail.com", name: "vinoth" },
      to: [{ email: toEmail, name: toName || "" }],
      subject,
      htmlContent,
    };

    const response = await emailApi.sendTransacEmail(emailData);

    console.log("Email sent successfully:", {
      to: toEmail,
      name: toName,
      subject,
      messageId: response.messageId,
    });

    return res.status(200).json({
      success: true,
      message: "Email sent successfully",
      data: {
        to: toEmail,
        name: toName,
        subject,
        messageId: response.messageId,
      },
    });
  } catch (err: any) {
    console.error("Failed to send email:", err.response?.body || err.message || err);
    return res.status(500).json({
      success: false,
      message: "Failed to send email",
      error: err.message,
    });
  }
};

export const listpendingApplications = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ message: "Not authorized" });

    let filter: any = { paymentStatus: "Unpaid" };


    if (user.role === "superadmin") {

      filter = { ...filter };
    } else if (user.role === "admin") {

      filter = { ...filter, instituteId: user.instituteId };
    } else if (user.role === "user") {

      filter = { ...filter, instituteId: user.instituteId, userId: user._id };
    }


    if (req.query.academicYear) filter.academicYear = req.query.academicYear;
    if (req.query.instituteId) filter.instituteId = req.query.instituteId;
    if (req.query.applicationId) {
      filter.applicationId = { $regex: req.query.applicationId, $options: "i" };
    }
    if (req.query.applicantName) {
      filter.applicantName = { $regex: req.query.applicantName, $options: "i" };
    }


    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;

    const options = {
      page,
      limit,
      sort: { createdAt: -1 },
      populate: [{ path: "institute", select: "name" }],
    };

    const applications = await (Application as any).paginate(filter, options);

    res.status(200).json({
      success: true,
      message: "Unpaid applications fetched successfully",
      applications,
    });
  } catch (error: any) {
    console.error("Error fetching unpaid applications:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};
export const createApplication = async (req: AuthRequest, res: Response) => {
  try {
    // ✅ Parse text data (may come as JSON strings in multipart)
    let bodyData: any = {};
    if (typeof req.body.personalData === "string") {
      bodyData.personalData = JSON.parse(req.body.personalData);
    } else {
      bodyData.personalData = req.body.personalData || {};
    }

    if (typeof req.body.educationData === "string") {
      bodyData.educationData = JSON.parse(req.body.educationData);
    } else {
      bodyData.educationData = req.body.educationData || {};
    }
    console.log(req.body.program, "req.body.program")
    const instituteId = req.body.instituteId || req.user?.instituteId;
    const program = req.body.program
    const academicYear = req.body.academicYear;
    const leadId = req.body.leadId;


    // ✅ Joi validation
    const { error } = createApplicationSchema.validate({
      instituteId,
      program,
      academicYear,
      personalData: bodyData.personalData,
      educationData: bodyData.educationData,
    });

    if (error)
      return res.status(400).json({ success: false, message: error.message });

    const createdBy = req.user?.id;

    if (!createdBy)
      return res.status(401).json({ success: false, message: "Not authorized" });

    // ✅ Verify institute has a form configuration
    const formConfig = await FormManager.findOne({ instituteId });
    if (!formConfig) {
      return res.status(404).json({
        success: false,
        message: "Form configuration not found for this institute",
      });
    }

    // ✅ Handle uploaded files and attach filenames to respective fields
    const files = req.files as Express.Multer.File[];

    if (files && files.length > 0) {
      files.forEach((file) => {
        const fieldName = file.fieldname;

        // Attach uploaded file name to personalData or educationData
        if (formConfig.personalFields.some((f: any) => f.fieldName === fieldName)) {
          bodyData.personalData[fieldName] = file.filename;
        } else if (
          formConfig.educationFields.some((f: any) => f.fieldName === fieldName)
        ) {
          bodyData.educationData[fieldName] = file.filename;
        }
      });
    }


    const applicationData: any = {
      instituteId,
      program,
      userId: createdBy,
      academicYear,
      personalData: bodyData.personalData,
      educationData: bodyData.educationData,
      applicantName: bodyData.personalData["Full Name"],
      courseCode: bodyData.courseCode,
      paymentStatus: bodyData.paymentStatus || "Unpaid",
      status: "Pending",
    };


    if (leadId) {
      applicationData.leadId = leadId;
    }


    const application = await Application.create(applicationData);

    if (leadId) {
      await LeadModel.findOneAndUpdate(
        { leadId },
        {
          applicationId: application._id,
        },
        { new: true }
      );
    }

    res.status(200).json({
      success: true,
      message: "Application submitted successfully",
      data: application,
    });
  } catch (error: any) {
    console.error("❌ Error creating application:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};


export const listApplications = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user
    if (!user) return res.status(401).json({ message: 'Not authorized' })

    let filter: any = {}


    if (user.role === 'superadmin') {
      filter = {}
    } else if (user.role === 'admin') {
      filter = { instituteId: user.instituteId }
    } else if (user.role === 'user') {
      filter = { instituteId: user.instituteId, userId: user._id }
    }

    // 🎯 Optional filters
    if (req.query.academicYear) filter.academicYear = req.query.academicYear
    if (req.query.instituteId) filter.instituteId = req.query.instituteId
    if (req.query.paymentStatus) filter.paymentStatus = req.query.paymentStatus;

    if (req.query.applicationId) {
      filter.applicationId = { $regex: req.query.applicationId, $options: "i" };
    }

    if (req.query.applicantName) {
      filter.applicantName = { $regex: req.query.applicantName, $options: "i" };
    }

    if (req.query.startDate || req.query.endDate) {
      const dateFilter: any = {};

      if (req.query.startDate) {
        const start = new Date(req.query.startDate as string);
        start.setHours(0, 0, 0, 0);
        dateFilter.$gte = start;
      }

      if (req.query.endDate) {
        const end = new Date(req.query.endDate as string);
        end.setHours(23, 59, 59, 999);
        dateFilter.$lte = end;
      }
      filter.createdAt = dateFilter;
    }
    const page = Number(req.query.page) || 1
    const limit = Number(req.query.limit) || 10
    const options = {
      page,
      limit,
      sort: { createdAt: -1 },
      populate: [
        { path: 'institute', select: 'name ' }
      ]
    }

    const applications = await (Application as any).paginate(filter, options)
    res.status(200).json({
      success: true,
      message: 'Applications fetched successfully',
      pagination: {
        totalDocs: applications.totalDocs,
        totalPages: applications.totalPages,
        currentPage: applications.page,
        limit: applications.limit
      },
      data: applications.docs
    })
  } catch (error: any) {
    console.error('Error fetching applications:', error)
    res.status(500).json({ success: false, message: error.message })
  }
}

// 🔍 Get Single Application
export const getApplication = async (req: Request, res: Response) => {
  try {
    const application = await Application.findById(req.params.id).populate('userId', 'firstname lastname role instituteId');

    if (!application) {
      return res.status(404).json({ success: false, message: 'Application not found' });
    }

    res.status(200).json({ success: true, data: application });
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// ✏️ Update Application (admin/superadmin only)
export const updateApplication = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ message: "Not authorized" });

    const application = await Application.findById(req.params.id);
    if (!application) {
      return res
        .status(404)
        .json({ success: false, message: "Application not found" });
    }



    // Parse personal & education data (may come as JSON string)
    const bodyData: any = {};
    bodyData.personalData =
      typeof req.body.personalData === "string"
        ? JSON.parse(req.body.personalData)
        : req.body.personalData || {};

    bodyData.educationData =
      typeof req.body.educationData === "string"
        ? JSON.parse(req.body.educationData)
        : req.body.educationData || {};

    const instituteId = req.body.instituteId || application.instituteId;
    const academicYear = req.body.academicYear || application.academicYear;
    const program = req.body.program

    // ✅ Validate base fields
    const { error } = createApplicationSchema.validate({
      instituteId,
      program,
      academicYear,
      personalData: bodyData.personalData,
      educationData: bodyData.educationData,
    });

    if (error)
      return res.status(400).json({ success: false, message: error.message });

    // ✅ Ensure form configuration exists
    const formConfig = await FormManager.findOne({ instituteId });
    if (!formConfig) {
      return res.status(404).json({
        success: false,
        message: "Form configuration not found for this institute",
      });
    }

    // ✅ Handle uploaded files
    const files = req.files as Express.Multer.File[];
    if (files && files.length > 0) {
      files.forEach((file) => {
        const fieldName = file.fieldname;

        if (formConfig.personalFields.some((f: any) => f.fieldName === fieldName)) {
          bodyData.personalData[fieldName] = file.filename;
        } else if (formConfig.educationFields.some((f: any) => f.fieldName === fieldName)) {
          bodyData.educationData[fieldName] = file.filename;
        }
      });
    }

    // ✅ Safely update application fields
    application.personalData = {
      ...application.personalData,
      ...bodyData.personalData,
    };

    application.educationData = {
      ...application.educationData,
      ...bodyData.educationData,
    };

    application.academicYear = academicYear;
    application.instituteId = instituteId;
    application.program = program;

    // ✅ Update new fields (added recently)
    application.applicantName =
      bodyData.personalData["Full Name"] ||
      bodyData.personalData.fullname ||
      application.applicantName;

    application.courseCode = req.body.courseCode || application.courseCode;

    application.paymentStatus =
      req.body.paymentStatus || application.paymentStatus || "Unpaid";

    await application.save();
    await application.populate("userId");

    return res.status(200).json({ success: true, data: application });
  } catch (error: any) {
    console.error("❌ Error updating application:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
};
export const updatePaymentStatus = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user;
    if (!user)
      return res.status(401).json({ success: false, message: "Not authorized" });

    const { id } = req.params;
    const { paymentStatus } = req.body;

    if (!paymentStatus) {
      return res.status(400).json({
        success: false,
        message: "Payment status is required",
      });
    }

    // ✅ Optional: restrict valid statuses
    const validStatuses = ["Paid", "Unpaid", "Partially"];
    if (!validStatuses.includes(paymentStatus)) {
      return res.status(400).json({
        success: false,
        message: `Invalid payment status. Must be one of: ${validStatuses.join(
          ", "
        )}`,
      });
    }

    // ✅ Find and update the application
    const updatedApplication = await Application.findByIdAndUpdate(
      id,
      { paymentStatus },
      { new: true }
    )

    if (!updatedApplication) {
      return res.status(404).json({
        success: false,
        message: "Application not found",
      });
    }

    return res.status(200).json({
      success: true,
      message: `Payment status updated to "${paymentStatus}"`,
      data: updatedApplication,
    });
  } catch (error: any) {
    console.error("❌ Error updating payment status:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Failed to update payment status",
    });
  }
};



// 🗑️ Delete Application (admin/superadmin only)
export const deleteApplication = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user
    if (!user) return res.status(401).json({ message: 'Not authorized' })

    if (user.role === 'user') {
      return res.status(403).json({ message: 'Access denied' })
    }

    const deleted = await Application.findByIdAndDelete(req.params.id)
    if (!deleted) return res.status(404).json({ message: 'Application not found' })

    res.status(200).json({ success: true, message: 'Application deleted successfully' })
  } catch (error: any) {
    res.status(500).json({ success: false, message: error.message })
  }
}
