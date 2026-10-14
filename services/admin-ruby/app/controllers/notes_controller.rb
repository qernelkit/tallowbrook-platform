# frozen_string_literal: true

class NotesController < ApplicationController
  def create
    note = Note.create!(author: current_staff, case_reference: params.require(:case_reference))
    SealedNotes.new.seal(note, params.require(:body))
    redirect_to note_path(note)
  end

  def show
    @note = Note.find(params[:id])
    @body = SealedNotes.new.open(@note) if @note.sealed?
  end
end
