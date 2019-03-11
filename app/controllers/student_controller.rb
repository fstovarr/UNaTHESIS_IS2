class StudentController < ApplicationController
  def initialize
    super User.user_type_ids.slice 'student'
  end

  def change_password
    user = User.find_by email: @current_user.email
    # user.
  end
  
  def download_pdf
    thesis_project = @current_user.thesis_projects.last
    
    send_file(
      "#{Rails.root}/#{thesis_project.document}",
      filename: "#{ thesis_project.title }.pdf",
      type: "application/pdf"
      )
    rescue => error
      if Rails.env.production?
        render json: { error: "Bad request" }, status: :unauthorized
      else
        render json: { error: error }, status: :unauthorized
      end
    end
    
  end