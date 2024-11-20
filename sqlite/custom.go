package sqlite

import "context"

func AllIDs(ctx context.Context, db DB) ([]int, error) {
	// query
	const sqlstr = `SELECT id FROM oauth_tokens order by updated_at desc`
	// run
	logf(sqlstr)
	rows, err := db.QueryContext(ctx, sqlstr)
	if err != nil {
		return nil, logerror(err)
	}
	defer rows.Close()
	// process
	var res []int
	for rows.Next() {
		ot := struct {
			ID int
		}{}
		// scan
		if err := rows.Scan(&ot.ID); err != nil {
			return nil, logerror(err)
		}
		res = append(res, ot.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, logerror(err)
	}
	return res, nil
}
