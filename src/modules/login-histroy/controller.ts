import { Request, Response } from 'express';
import LoginHistory from './model'; // adjust path to your model
import { AuthRequest } from '../../middlewares/auth'; // adjust path
import { createLoginHistorySchema } from './login.sanitize';

export const createLoginHistory = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    const { error, value } = createLoginHistorySchema.validate(req.body, { allowUnknown: true });
    if (error) {
      return res.status(400).json({ success: false, message: error.message });
    }

    const history = await LoginHistory.create({
      instituteId: user.instituteId,
      userId: user.id,
      role: user.role,
      lastLoginTime: new Date(),
      ...value, 
    });

    return res.status(201).json({
      success: true,
      message: 'Login history recorded successfully',
      data: history,
    });
  } catch (error: any) {
    console.error('Error creating login history:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while creating login history',
      error: error.message,
    });
  }
};

export const listLoginHistories = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user;
    if (!user) return res.status(401).json({ message: 'Not authorized' });

    // Pagination parameters
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;

    const { instituteId, userId, role, startDate, endDate } = req.query;
    let filter: any = {};

    // Role-based filtering
    if (user.role === 'superadmin') {
      if (instituteId) filter.instituteId = instituteId;
      if (userId) filter.userId = userId;
      if (role) filter.role = role;
    } else if (user.role === 'admin') {
      filter.instituteId = user.instituteId;
      filter.role = 'user';
      if (userId) filter.userId = userId;
    } else if (user.role === 'user') {
      filter.userId = user.id;
      filter.instituteId = user.instituteId;
    }

    // Date filtering
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) {
        const start = new Date(startDate as string);
        start.setHours(0, 0, 0, 0);
        filter.createdAt.$gte = start;
      }
      if (endDate) {
        const end = new Date(endDate as string);
        end.setHours(23, 59, 59, 999);
        filter.createdAt.$lte = end;
      }
    }

    // Paginated query
    const histories = await (LoginHistory as any).paginate(filter, {
      page,
      limit,
      sort: { createdAt: -1 },
      populate: { path: 'user', select: 'firstname lastname email role' },
    });

    return res.status(200).json({
      success: true,
      histories,
    });
  } catch (error: any) {
    console.error('Error fetching login histories:', error);
    res.status(500).json({ success: false, message: error.message });
  }
};
