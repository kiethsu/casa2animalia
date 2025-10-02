// salesByYear.js

const mongoose = require('mongoose');
const Payment = require('./models/Payment'); // adjust path if needed

// ► Replace this with your actual MongoDB connection string:
const MONGODB_URI = 'mongodb://localhost:27017/smartvet';

async function runAggregation() {
  try {
    // 1) Perform aggregation: group payments by year(paidAt), sum(amount)
    const results = await Payment.aggregate([
      {
        $group: {
          _id: { $year: '$paidAt' },
          totalSales: { $sum: '$amount' }
        }
      },
      { $sort: { '_id': 1 } },
      {
        $project: {
          _id:     0,
          year:    '$_id',
          totalSales: 1
        }
      }
    ]);

    // 2) Print the results to console
    console.log('Sales by Year:');
    results.forEach(doc => {
      console.log(`  ${doc.year}: ₱${doc.totalSales.toLocaleString()}`);
    });

    process.exit(0);
  } catch (err) {
    console.error('Aggregation error:', err);
    process.exit(1);
  }
}

async function main() {
  // Connect to MongoDB
  await mongoose.connect(MONGODB_URI, {
    useNewUrlParser:    true,
    useUnifiedTopology: true
  });
  console.log('▶ Connected to MongoDB.');

  // Run the sales‐by‐year aggregation
  await runAggregation();
}

main();
