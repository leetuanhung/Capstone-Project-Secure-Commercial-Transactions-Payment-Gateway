# ✅ RENDER DEPLOYMENT CHECKLIST

## 📝 Pre-Deployment

- [ ] Code đã được test locally
- [ ] Database migrations đã được chuẩn bị (nếu có)
- [ ] Environment variables đã được list đầy đủ
- [ ] Health check endpoint hoạt động (`/health`)
- [ ] CORS settings phù hợp với frontend domain
- [ ] API keys (Stripe) đã được chuẩn bị

## 🔐 Security

- [ ] `.env` file KHÔNG được commit vào Git
- [ ] `SECRET_KEY` sẽ được auto-generate trên Render
- [ ] Stripe keys sẽ được set qua Environment Variables
- [ ] Database password auto-generate
- [ ] HTTPS sẽ được enable mặc định
- [ ] Rate limiting đã được config

## 📦 Files Created

- [x] `render.yaml` - Blueprint configuration
- [x] `backend/Dockerfile.render` - Production Dockerfile
- [x] `build.sh` - Build script
- [x] `start.sh` - Start script
- [x] `backend/.dockerignore` - Optimize Docker build
- [x] `DEPLOYMENT_RENDER.md` - Deployment guide
- [x] Health check endpoint in `main.py`

## 🚀 Deployment Steps

### Option 1: Automatic Blueprint Deployment (Recommended)

1. [ ] Push code to GitHub:
   ```bash
   git add .
   git commit -m "Add Render deployment config"
   git push origin main
   ```

2. [ ] Go to [Render Dashboard](https://dashboard.render.com)
   - Click "New +" → "Blueprint"
   - Connect GitHub repository
   - Render auto-detects `render.yaml`
   - Click "Apply"

3. [ ] Configure Environment Variables in Render Dashboard:
   ```
   STRIPE_SECRET_KEY=sk_test_...
   STRIPE_PUBLISHABLE_KEY=pk_test_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   ```

4. [ ] Wait for deployment to complete (5-10 minutes)

5. [ ] Test endpoints:
   ```bash
   curl https://your-app.onrender.com/health
   ```

### Option 2: Manual Service Creation

1. [ ] Create PostgreSQL Database
   - Name: `nt219-postgres`
   - Plan: Free
   - Region: Singapore

2. [ ] Create Web Service
   - Name: `nt219-backend`
   - Environment: Docker
   - Dockerfile: `./backend/Dockerfile.render`
   - Plan: Free

3. [ ] Connect services via environment variables

## 🧪 Post-Deployment Testing

- [ ] Health check: `GET /health`
- [ ] Database connection working
- [ ] User registration: `POST /auth/register`
- [ ] User login: `POST /auth/login`
- [ ] Product listing: `GET /payment/products`
- [ ] Payment creation works
- [ ] Stripe webhooks configured

## 📊 Monitoring

- [ ] Check deployment logs in Render dashboard
- [ ] Verify health check passes
- [ ] Monitor response times
- [ ] Check error logs

## 🔧 Environment Variables to Set

### Required
```env
STRIPE_SECRET_KEY=
STRIPE_PUBLISHABLE_KEY=
STRIPE_WEBHOOK_SECRET=
```

### Database (Auto-configured by Render)
```env
database_hostname=
database_port=
database_username=
database_password=
database_name=
```

### Optional
```env
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM_EMAIL=
ALLOWED_ORIGINS=
FRAUD_MODEL_PATH=
```

## ⚠️ Common Issues

### Issue: Database connection failed
**Solution**: Check that database service is running and env vars are correct

### Issue: Health check failing
**Solution**: Verify `/health` endpoint returns 200 OK

### Issue: Port binding error
**Solution**: Ensure app binds to `0.0.0.0:$PORT`

### Issue: Static files not loading
**Solution**: Check StaticFiles mount paths are correct

## 📈 Performance Tips

- [ ] Enable CDN for static assets
- [ ] Use connection pooling for database
- [ ] Implement caching where appropriate
- [ ] Monitor memory usage (Free tier: 512MB)

## 💰 Cost Tracking

- PostgreSQL Free: $0/month (1GB limit)
- Web Service Free: $0/month (750 hours)
- **Total**: $0/month

**Note**: Free services sleep after 15 minutes of inactivity

## 🎯 Next Steps After Deployment

1. [ ] Update frontend API URL
2. [ ] Configure Stripe webhook URL in Stripe Dashboard
3. [ ] Setup monitoring/alerting
4. [ ] Configure custom domain (optional)
5. [ ] Add SSL certificate (auto-provided by Render)

## 📚 Resources

- [Render Docs](https://render.com/docs)
- [FastAPI on Render](https://render.com/docs/deploy-fastapi)
- [Blueprint Spec](https://render.com/docs/blueprint-spec)

---

**Date Created**: December 22, 2025
**Last Updated**: December 22, 2025
