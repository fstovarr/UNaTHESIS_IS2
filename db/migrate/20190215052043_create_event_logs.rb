class CreateEventLogs < ActiveRecord::Migration[5.2]
  def change
    create_table :event_logs do |t|
      t.string :name, null: false
      t.references :thesis_project_user, foreign_key: true
      t.timestamps
    end
  end
end
