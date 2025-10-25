module.exports = function viewAsHr(req, _res, next) {
  if (req.user && String(req.user.role).toLowerCase() === 'admin') {
    req.viewAsHrId = (req.get('x-view-as-hr') || req.query.hrId || req.body.hrId || '').trim() || null;
    if (req.viewAsHrId) {
      console.log(`[viewAsHr] admin ${req.user.userId} viewing as HR ${req.viewAsHrId} -> ${req.method} ${req.originalUrl}`);
    }
  }
  next();
};
