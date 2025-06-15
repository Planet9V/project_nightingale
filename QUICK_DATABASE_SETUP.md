# Quick Database Setup Guide

## 1. Execute Database Schema (Required First!)

1. Go to your Supabase SQL Editor:
   https://yopfdfezojpdnpgbolhu.supabase.co/dashboard/project/yopfdfezojpdnpgbolhu/sql

2. Copy the entire contents of `supabase/schema.sql`

3. Paste and run it in the SQL Editor

4. You should see "Success. No rows returned" - this is expected!

## 2. Test Your Connection

Run the test script:

```bash
node test-supabase-connection.js
```

If successful, you'll see:
- ✅ Successfully connected to Supabase!
- ✅ All CRUD operations working
- ✅ Storage bucket accessible

## 3. Common Issues

### "relation 'prospects' does not exist"
→ You need to run the schema.sql first!

### "Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY"
→ Check your .env file has the correct values

### Connection timeouts
→ Check your internet connection and Supabase project status

## 4. Next Steps

Once tests pass:
1. Remove the test script: `rm test-supabase-connection.js`
2. Start using the database service in your code
3. Import existing data if needed

## Quick Reference

```typescript
import { db } from './src/services/database';

// Create a prospect
const prospect = await db.createProspect({
  account_id: 'A-001',
  company_name: 'Example Corp',
  sector: 'Energy',
  criticality: 8
});

// Get threats
const threats = await db.listThreats({
  minSeverity: 7,
  daysBack: 30
});
```