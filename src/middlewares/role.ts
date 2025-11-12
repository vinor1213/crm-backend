import { Request, Response, NextFunction } from 'express';
import { AuthRequest } from './auth';

export const permit = (...allowed: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const role = req.user?.role;
    if (!role || !allowed.includes(role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
};
