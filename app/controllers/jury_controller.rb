class JuryController < ApplicationController
    skip_before_action :verify_authenticity_token

    def search_projects
        authenticate_request!
        projects = @current_user.thesis_projects
        titles = []
        projects.each do |project|
            titles << {title: project.title, id: project.id}
        end
        
        render json: titles
    end

    def add_comment
        authenticate_request!
        msg = ""
        if check_user
            comment = Comment.where(users_id: @current_user.id,
                thesis_project_id: jury_params[:thesis_project_id])
            if comment == nil
                users_id = {:users_id => @current_user.id}
                params[:jury].merge! users_id
                comment = Comment.create(jury_params)
                if comment.id != nil
                    msg = "Created and Saved"
                else
                    msg = "Created and Didn't Saved"
                end
    
            else
                comment.title = jury_params[:title]
                comment.content = jury_params[:content]
                if comment.save
                    msg = "Updated"
                else
                    msg = "Couldn't be updated"
                end
            end
             
            render json: {message: msg}
        else
            render json: {:message => "Invalid Request"}, status: :unauthorized
        end
    end

    def add_questions
        authenticate_request!

        if check_user
            questions = Question.where(user_id: @current_user.id,
                thesis_project_id: jury_params[:thesis_project_id])
            if questions.empty?
                params[:jury][:questions].each do |question|
                    if question != ""
                        questions = Question.create(
                            question: question,
                            user_id: @current_user.id,
                            thesis_project_id: jury_params[:thesis_project_id]
                        )
                    end                    
                end
            else
                # new_questions = params[:jury][:questions]
                # if new_questions.length == questions.length
                #     i = 0                    
                #     questions.each do |question_obj|
                #         question_obj.question = new_questions[i].question
                #     end                                     
                # elsif new_questions.length < question.length
                        
                # else
                    
                # end
            end
        else
            render json: {:message => "Invalid Request"}, status: :unauthorized
        end
        render json: questions
    end
    
    def get_questions
        authenticate_request!

        questions = []
        if check_user
            questions = Question.where(
                user_id: @current_user.id,
                thesis_project_id: params[:thesis_project_id]
                )
        end    
        render json: questions
    end    
    
    private

    def check_user
        @current_user.user_type_id == UserType.find_by(name: "Jury").id
    end
    
    def jury_params
        params.require(:jury).permit(:title, :content, :thesis_project_id, :users_id)
    end

end
